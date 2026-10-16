#!/usr/bin/env python3
"""
sdr/adsb_tracker.py - ADS-B / Mode-S aircraft tracker with its own decoder.
==========================================================================

Description
-----------
Tracks aircraft by demodulating the 1090 MHz Mode-S downlink in software - no
dump1090 required. The module implements:

* an RTL-SDR capture path (``rtl_sdr -f 1090000000 -s 2000000``) that can also
  read a previously recorded IQ file, so a survey can be processed offline
* Mode-S preamble detection and PPM slicing of both 56-bit short and 112-bit
  long frames
* the Mode-S CRC-24 (polynomial 0xFFF409) used to validate every frame
* ADS-B DF17/DF18 extended squitter parsing: identification (callsign and
  category), airborne and surface position, barometric altitude, velocity
  (subtypes 1-4), aircraft status (squawk and emergency) and operational status
* global CPR (Compact Position Reporting) decoding, which needs one even and
  one odd position frame from the same aircraft
* a live Rich table, a per-aircraft JSON/CSV track log and event records in the
  shared SQLite database

This is receive-only: 1090 MHz is a broadcast you are permitted to receive.
Nothing here transmits, and aircraft operators are not identifiable individuals.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: rtl-sdr (rtl_sdr, optional - an IQ file works without a dongle);
              optional: rich (live table)
Licence     : MIT - receive-only (see docs/LEGAL.md)

Usage
-----
    sudo ./adsb_tracker.py --duration 60 --live
    sudo ./adsb_tracker.py --duration 300 --write
    ./adsb_tracker.py --input capture.iq --json
    ./adsb_tracker.py --hex 8D4840D6202CC371C32CE0576098   # decode one frame
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "lib",
    Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")) / "lib",
]
for _candidate in _LIB_CANDIDATES:
    if (_candidate / "cyberlib.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

try:
    from cyberlib import Config, Database, Hardware, Logger, colour, now_iso  # type: ignore
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: Mode-S CRC-24 generator including the implicit x^24 term (0x1FFF409)
CRC_POLY = 0x1FFF409
#: ADS-B identification character set, indexed by the 6-bit code
CALLSIGN_CHARS = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######"
#: Type codes that carry position, and whether they are surface messages
SURFACE_TYPE_CODES = range(5, 9)
AIRBORNE_TYPE_CODES = tuple(range(9, 19)) + tuple(range(20, 23))
EMERGENCY_CODES = {
    0: "no emergency", 1: "general emergency", 2: "lifeguard/medical",
    3: "minimum fuel", 4: "no communications", 5: "unlawful interference",
    6: "downed aircraft", 7: "reserved",
}


# --------------------------------------------------------------------------- #
# Bit helpers
# --------------------------------------------------------------------------- #
def bits_to_int(bits: Sequence[int]) -> int:
    """Convert a sequence of 0/1 integers to an integer.

    Args:
        bits: most-significant-bit-first sequence.

    Returns:
        The integer value.
    """
    value = 0
    for bit in bits:
        value = (value << 1) | (bit & 1)
    return value


def bytes_to_bits(data: bytes) -> List[int]:
    """Expand bytes into a list of bits.

    Args:
        data: the raw frame.

    Returns:
        A list of 0/1 integers, most significant bit first.
    """
    out: List[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            out.append((byte >> shift) & 1)
    return out


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Pack a bit list into bytes.

    Args:
        bits: the bit list (length must be a multiple of 8).

    Returns:
        The packed bytes.
    """
    out = bytearray()
    for index in range(0, len(bits) - len(bits) % 8, 8):
        out.append(bits_to_int(bits[index:index + 8]))
    return bytes(out)


def mode_s_crc(bits: Sequence[int]) -> int:
    """Compute the Mode-S CRC-24 over a bit sequence.

    Implements the polynomial division of the message bits by
    ``x^24 + x^23 + ... + 1`` (generator ``0xFFF409``), which is what the
    transponder appends so that the whole frame divides to zero.

    Args:
        bits: the frame bits *excluding* the 24-bit parity field.

    Returns:
        The 24-bit remainder, i.e. the parity that should follow *bits*.
    """
    work = list(bits) + [0] * 24
    polynomial_bits = [int(bit) for bit in bin(CRC_POLY)[2:]]
    for index in range(len(bits)):
        if work[index]:
            for offset, poly_bit in enumerate(polynomial_bits):
                work[index + offset] ^= poly_bit
    return bits_to_int(work[-24:])


def hexdump_frame(frame: bytes) -> str:
    """Return a frame as an upper-case hex string.

    Args:
        frame: the raw frame bytes.

    Returns:
        The hexadecimal representation.
    """
    return frame.hex().upper()


# --------------------------------------------------------------------------- #
# CPR (Compact Position Reporting)
# --------------------------------------------------------------------------- #
def cpr_nl(latitude: float) -> int:
    """Return the number of CPR longitude zones at a latitude.

    Args:
        latitude: latitude in degrees.

    Returns:
        The NL value (1..59).
    """
    if latitude >= 87.0 or latitude <= -87.0:
        return 1
    cos_lat = math.cos(math.radians(abs(latitude)))
    numerator = 1.0 - math.cos(math.pi / 30.0)
    denominator = cos_lat * cos_lat
    argument = 1.0 - numerator / denominator
    if argument < -1.0 or argument > 1.0:
        return 1
    return int(math.floor(2.0 * math.pi / math.acos(argument)))


def decode_cpr_global(even: int, odd: int, even_surface: bool = False,
                      odd_surface: bool = False) -> Optional[Tuple[float, float]]:
    """Decode a global CPR position from an even/odd frame pair.

    Implements the air/global CPR algorithm of DO-260B: the latitude zone
    (``j``) is recovered from the fractional latitudes of both frames, then the
    longitude zone (``m``) from the fractional longitudes.

    Args:
        even: the 34-bit CPR payload (latitude and longitude) of the even frame.
        odd: the same payload from the odd frame.
        even_surface: True when the even frame is a surface position message.
        odd_surface: True when the odd frame is a surface position message.

    Returns:
        ``(latitude, longitude)`` in degrees, or ``None`` when the pair cannot
        be decoded (the frames are too far apart, or the latitude zone counts
        disagree, which happens when the two frames are not really a pair).
    """
    surface = even_surface and odd_surface
    span = 90.0 if surface else 360.0

    lat_even_f = ((even >> 17) & 0x1FFFF) / 131072.0
    lat_odd_f = ((odd >> 17) & 0x1FFFF) / 131072.0
    lon_even_f = (even & 0x1FFFF) / 131072.0
    lon_odd_f = (odd & 0x1FFFF) / 131072.0

    dlat_even = span / 60.0
    dlat_odd = span / 59.0

    j = math.floor(59 * lat_even_f - 60 * lat_odd_f + 0.5)
    latitude_even = dlat_even * ((j % 60) + lat_even_f)
    latitude_odd = dlat_odd * ((j % 59) + lat_odd_f)
    if latitude_even >= 270.0:
        latitude_even -= 360.0
    if latitude_odd >= 270.0:
        latitude_odd -= 360.0

    # The two frames must agree on the latitude zone count to be a valid pair
    if cpr_nl(latitude_even) != cpr_nl(latitude_odd):
        return None

    if j % 2 == 0:
        latitude = latitude_even
        nl = cpr_nl(latitude_even)
        ni = max(nl, 1)
        dlon = span / max(nl, 1)
        fraction = lon_even_f
    else:
        latitude = latitude_odd
        nl = cpr_nl(latitude_odd)
        ni = max(nl - 1, 1)
        dlon = span / max(nl - 1, 1)
        fraction = lon_odd_f

    m = math.floor(lon_even_f * max(nl - 1, 1) - lon_odd_f * nl + 0.5)
    longitude = dlon * ((m % ni) + fraction)
    if longitude > 180.0:
        longitude -= 360.0
    return latitude, longitude


def decode_altitude(field: int) -> Optional[int]:
    """Decode a 12-bit altitude field from an extended squitter or a DF4/DF20 reply.

    Two encodings exist in the Mode-S altitude field:

    * ``Q = 1`` - 25 ft increments, still used by every modern transponder and
      the encoding that ADS-B actually transmits. Decoded exactly here.
    * ``Q = 0`` - the old Gillham (Mode C) 100 ft code. DO-260B deprecated this
      encoding and the ADSB altitude field does not carry the D1 bit of the
      13-bit Mode C code, so a Q=0 value cannot be reconstructed
      unambiguously: ``None`` is returned and the caller ignores the value
      rather than reporting a guess as an altitude.

    Args:
        field: the 12-bit altitude field.

    Returns:
        Altitude in feet, or ``None`` when the field is empty or uses the
        deprecated Gillham encoding.
    """
    if field == 0:
        return None
    if field & 0x10:  # Q bit: 25 ft increments
        value = ((field & 0x0FE0) >> 1) | (field & 0x000F)
        return value * 25 - 1000
    return None


def gray_to_binary(gray: int) -> int:
    """Convert a Gray-coded integer to binary.

    Args:
        gray: the Gray-coded value.

    Returns:
        The binary value.
    """
    value = gray
    shift = 1
    while (gray >> shift) > 0:
        value ^= gray >> shift
        shift += 1
    return value


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
@dataclass
class Aircraft:
    """One tracked aircraft."""

    icao: str
    callsign: str = ""
    category: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_ft: Optional[int] = None
    altitude_source: str = ""
    ground_speed_kt: Optional[float] = None
    track_deg: Optional[float] = None
    vertical_rate_fpm: Optional[int] = None
    squawk: str = ""
    emergency: str = ""
    on_ground: bool = False
    messages: int = 0
    position_messages: int = 0
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    positions: List[Tuple[float, float, str]] = field(default_factory=list)
    frames: List[str] = field(default_factory=list)
    even_position: Optional[Tuple[int, str]] = None
    odd_position: Optional[Tuple[int, str]] = None

    @property
    def label(self) -> str:
        """A short human label for the aircraft."""
        return self.callsign.strip() or self.icao

    @property
    def distance_sample(self) -> str:
        """A compact position string for tables."""
        if self.latitude is None or self.longitude is None:
            return "—"
        return f"{self.latitude:.4f},{self.longitude:.4f}"

    def as_dict(self) -> Dict[str, Any]:
        """Return the aircraft as a plain dictionary."""
        return {
            "icao": self.icao,
            "callsign": self.callsign.strip(),
            "category": self.category,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude_ft": self.altitude_ft,
            "altitude_source": self.altitude_source,
            "ground_speed_kt": self.ground_speed_kt,
            "track_deg": self.track_deg,
            "vertical_rate_fpm": self.vertical_rate_fpm,
            "squawk": self.squawk,
            "emergency": self.emergency,
            "on_ground": self.on_ground,
            "messages": self.messages,
            "position_messages": self.position_messages,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "positions": [{"lat": lat, "lon": lon, "ts": ts} for lat, lon, ts in self.positions],
            "frames": self.frames[-8:],
        }


# --------------------------------------------------------------------------- #
# Decoder
# --------------------------------------------------------------------------- #
class ModeSDecoder:
    """Parses Mode-S / ADS-B frames that have already passed CRC validation."""

    @staticmethod
    def parse(frame: bytes) -> Optional[Dict[str, Any]]:
        """Parse a raw Mode-S frame.

        Args:
            frame: the frame bytes (7 or 14 bytes).

        Returns:
            A dictionary of decoded fields, ``None`` when the CRC fails or the
            downlink format is not supported.
        """
        if len(frame) not in (7, 14):
            return None
        bits = bytes_to_bits(frame)
        if mode_s_crc(bits[:-24]) != bits_to_int(bits[-24:]):
            return None

        downlink_format = bits_to_int(bits[0:5])
        result: Dict[str, Any] = {
            "df": downlink_format,
            "raw": hexdump_frame(frame),
            "length": len(frame) * 8,
            "type_code": None,
        }

        if downlink_format in (17, 18):
            result.update(ModeSDecoder._parse_extended_squitter(bits))
        elif downlink_format == 11:
            result["icao"] = "".join(f"{b:01d}" for b in bits[8:32])
        elif downlink_format in (4, 5, 20, 21):
            result["altitude_ft"] = decode_altitude(bits_to_int(bits[19:31]))
            result["squawk"] = ModeSDecoder._squawk(bits_to_int(bits[32:45])) \
                if len(bits) >= 45 else ""
        else:
            return None
        return result

    @staticmethod
    def _parse_extended_squitter(bits: List[int]) -> Dict[str, Any]:
        """Parse an ADS-B extended squitter (DF17/DF18).

        Args:
            bits: the frame bits.

        Returns:
            Decoded fields.
        """
        header = {
            "ca": bits_to_int(bits[5:8]),
            "icao": "".join(f"{bit:01d}" for bit in bits[8:32]),
            "type_code": bits_to_int(bits[32:37]),
        }
        icao_hex = f"{bits_to_int(bits[8:32]):06X}"
        header["icao"] = icao_hex
        type_code = header["type_code"]
        me = bits[32:88]

        if 1 <= type_code <= 4:
            header["kind"] = "identification"
            header["callsign"], header["category"] = ModeSDecoder._identification(me)
        elif type_code in SURFACE_TYPE_CODES:
            header["kind"] = "surface_position"
            header.update(ModeSDecoder._surface_position(me))
        elif type_code in AIRBORNE_TYPE_CODES:
            header["kind"] = "airborne_position"
            header.update(ModeSDecoder._airborne_position(me))
        elif type_code == 19:
            header["kind"] = "velocity"
            header.update(ModeSDecoder._velocity(me))
        elif type_code == 28:
            header["kind"] = "status"
            header.update(ModeSDecoder._status(me))
        elif type_code == 29:
            header["kind"] = "target_state"
        elif type_code == 31:
            header["kind"] = "operational_status"
        else:
            header["kind"] = "other"
        return header

    @staticmethod
    def _identification(me: Sequence[int]) -> Tuple[str, str]:
        """Decode the callsign and emitter category from an identification ME.

        Args:
            me: the 56-bit ME field.

        Returns:
            A ``(callsign, category)`` pair.
        """
        callsign = ""
        for index in range(8):
            code = bits_to_int(me[8 + index * 6: 14 + index * 6])
            callsign += CALLSIGN_CHARS[code] if 0 <= code < len(CALLSIGN_CHARS) else "#"
        category = f"cat {bits_to_int(me[5:8])}"
        return callsign.replace("_", " ").strip(), category

    @staticmethod
    def _airborne_position(me: Sequence[int]) -> Dict[str, Any]:
        """Decode an airborne position ME field.

        Args:
            me: the 56-bit ME field.

        Returns:
            Decoded altitude and CPR payload.
        """
        altitude = None
        if len(me) >= 20:
            altitude = decode_altitude(bits_to_int(me[8:20]))
        result: Dict[str, Any] = {
            "altitude_ft": altitude,
            "altitude_source": "barometric",
            "cpr_odd": me[21] == 1,
            "cpr": bits_to_int(me[22:56]),
            "latitude": None,
            "longitude": None,
        }
        return result

    @staticmethod
    def _surface_position(me: Sequence[int]) -> Dict[str, Any]:
        """Decode a surface position ME field.

        Args:
            me: the 56-bit ME field.

        Returns:
            Decoded ground speed, track and CPR payload.
        """
        speed_kt = None
        if len(me) >= 12:
            raw_speed = bits_to_int(me[5:12])
            if raw_speed:
                speed_kt = (raw_speed - 1) * (0.125 if me[12] else 1.0)
        track = None
        if len(me) >= 20:
            raw_track = bits_to_int(me[13:20])
            if raw_track:
                track = raw_track * (360.0 / 128.0)
        return {
            "ground_speed_kt": speed_kt,
            "track_deg": track,
            "cpr_odd": me[21] == 1,
            "cpr": bits_to_int(me[22:56]),
            "on_ground": True,
            "latitude": None,
            "longitude": None,
        }

    @staticmethod
    def _velocity(me: Sequence[int]) -> Dict[str, Any]:
        """Decode an airborne velocity ME field (subtypes 1-4).

        Args:
            me: the 56-bit ME field.

        Returns:
            Decoded ground speed, track and vertical rate.
        """
        subtype = bits_to_int(me[5:8])
        result: Dict[str, Any] = {"velocity_subtype": subtype}
        if subtype in (1, 2):
            scale = 4.0 if subtype == 2 else 1.0
            raw_ew = bits_to_int(me[14:24]) - 1
            raw_ns = bits_to_int(me[25:35]) - 1
            if bits_to_int(me[14:24]) == 0 or bits_to_int(me[25:35]) == 0:
                result["ground_speed_kt"] = None
                result["track_deg"] = None
            else:
                ew = raw_ew * scale if me[13] == 0 else -raw_ew * scale
                ns = raw_ns * scale if me[24] == 0 else -raw_ns * scale
                result["ground_speed_kt"] = round(math.hypot(ew, ns), 1)
                track = math.degrees(math.atan2(ew, ns))
                result["track_deg"] = round(track % 360.0, 1)
            source = me[35]
            raw_rate = bits_to_int(me[37:46]) - 1
            if raw_rate > 0:
                rate = raw_rate * 64
                result["vertical_rate_fpm"] = rate if me[36] == 0 else -rate
                result["vertical_rate_source"] = "barometric" if source == 0 else "gnss"
            else:
                result["vertical_rate_fpm"] = None
        elif subtype in (3, 4):
            raw_heading = bits_to_int(me[13:23])
            if raw_heading:
                result["track_deg"] = round(raw_heading * 360.0 / 1024.0, 1)
            raw_speed = bits_to_int(me[24:34])
            if raw_speed:
                result["ground_speed_kt"] = raw_speed if subtype == 3 else raw_speed * 4
            raw_rate = bits_to_int(me[37:46]) - 1
            if raw_rate > 0:
                rate = raw_rate * 64
                result["vertical_rate_fpm"] = rate if me[36] == 0 else -rate
        return result

    @staticmethod
    def _status(me: Sequence[int]) -> Dict[str, Any]:
        """Decode an aircraft status ME field (emergency and squawk).

        Args:
            me: the 56-bit ME field.

        Returns:
            Decoded emergency state and squawk.
        """
        subtype = bits_to_int(me[5:8])
        result: Dict[str, Any] = {"status_subtype": subtype}
        if subtype == 1:
            emergency_id = bits_to_int(me[8:11])
            result["emergency"] = EMERGENCY_CODES.get(emergency_id, "unknown")
            result["squawk"] = ModeSDecoder._squawk(bits_to_int(me[11:24]))
        return result

    @staticmethod
    def _squawk(field: int) -> str:
        """Decode a 13-bit Mode-A squawk field into four octal digits.

        Args:
            field: the 13-bit field.

        Returns:
            The four-digit squawk code, e.g. ``"7000"``.
        """
        digits = ((field >> 9) & 0xF, (field >> 5) & 0x7, (field >> 2) & 0x7, field & 0x3)
        return "".join(str(digit) if digit < 8 else "?" for digit in digits)


# --------------------------------------------------------------------------- #
# Demodulator
# --------------------------------------------------------------------------- #
class IqDemodulator:
    """Turns unsigned 8-bit IQ samples into candidate Mode-S frames."""

    def __init__(self, logger: Logger, sample_rate: int = 2_000_000,
                 threshold_factor: float = 2.0) -> None:
        """Create the demodulator.

        Args:
            logger: shared logger.
            sample_rate: capture sample rate in Hz (2 MHz recommended).
            threshold_factor: multiplier over the mean magnitude that counts as
                a signal; raise it in a noisy RF environment.
        """
        self.logger = logger
        self.sample_rate = sample_rate
        self.threshold_factor = threshold_factor
        #: samples per 0.5 µs
        self.half_microsecond = max(1, sample_rate // 2_000_000)
        self.preamble_positions = [0, 2, 7, 9]
        if sample_rate == 2_400_000:
            self.preamble_positions = [0, 2, 8, 10]
        self.frame_count = 0

    @staticmethod
    def magnitudes(block: bytes) -> List[float]:
        """Convert an IQ block to a magnitude list.

        Args:
            block: interleaved unsigned 8-bit I/Q samples.

        Returns:
            One magnitude value per complex sample (offset removed, summed
            absolute values - cheaper than a square root and monotonic).
        """
        values = list(block)
        magnitudes = []
        append = magnitudes.append
        for index in range(0, len(values) - 1, 2):
            i = values[index] - 128
            q = values[index + 1] - 128
            append(float((i * i + q * q)))
        return magnitudes

    def detect(self, block: bytes) -> List[bytes]:
        """Find and decode Mode-S frames in a sample block.

        Args:
            block: raw IQ bytes from rtl_sdr.

        Returns:
            A list of validated frame byte strings.
        """
        magnitude = self.magnitudes(block)
        if len(magnitude) < 240:
            return []
        total = sum(magnitude)
        if total <= 0:
            return []
        average = total / len(magnitude)
        threshold = average * self.threshold_factor

        frames: List[bytes] = []
        limit = len(magnitude) - 300
        index = 0
        step = self.half_microsecond
        while index < limit:
            spike = (magnitude[index] > threshold
                     and magnitude[index + 2 * step] > threshold
                     and magnitude[index + 7 * step] > threshold
                     and magnitude[index + 9 * step] > threshold)
            if not spike:
                index += step
                continue
            low = (magnitude[index + step] < threshold * 0.6
                   and magnitude[index + 8 * step] < threshold * 0.6)
            if not low:
                index += step
                continue

            header = self._sample_bits(magnitude, index + 16 * step, 5)
            downlink_format = bits_to_int(header)
            length_bits = 112 if downlink_format >= 16 else 56
            bit_values = self._sample_bits(magnitude, index + 16 * step, length_bits)
            if len(bit_values) != length_bits:
                index += 16 * step
                continue
            frame = bits_to_bytes(bit_values)
            if ModeSDecoder.parse(frame) is not None:
                frames.append(frame)
                self.frame_count += 1
                index += 16 * step + length_bits * 2 * step
                continue
            index += step
        return frames

    def _sample_bits(self, magnitude: Sequence[float], start: int,
                     count: int) -> List[int]:
        """Slice PPM bits out of a magnitude array.

        Args:
            magnitude: the magnitude array.
            start: sample index where the data section begins.
            count: number of bits to slice.

        Returns:
            A list of bits; a short list means the block ended mid-frame.
        """
        step = self.half_microsecond
        bits: List[int] = []
        for bit_index in range(count):
            first = start + bit_index * 2 * step
            second = first + step
            if second + step > len(magnitude):
                break
            first_power = max(magnitude[first:first + step])
            second_power = max(magnitude[second:second + step])
            bits.append(1 if first_power > second_power else 0)
        return bits


# --------------------------------------------------------------------------- #
# Tracker
# --------------------------------------------------------------------------- #
class AdsbTracker:
    """Capture, decode and report ADS-B traffic.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
    """

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                               "/opt/cyberdeck-arsenal")))
        self.output_dir = self.install_dir / "captures" / "adsb"
        self.frequency = int(config.get("sdr.adsb_frequency", 1_090_000_000))
        self.sample_rate = int(config.get("sdr.adsb_sample_rate", 2_000_000))
        self.gain = str(config.get("sdr.gain", "auto"))
        self.ppm = int(config.get("sdr.ppm", 0) or 0)
        self.device_index = int(config.get("sdr.device_index", 0) or 0)
        self.aircraft: Dict[str, Aircraft] = {}
        self.running = True
        self.demodulator = IqDemodulator(logger, self.sample_rate)
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)

    # -- capture ----------------------------------------------------------- #
    def rtl_command(self, duration: int) -> List[str]:
        """Build the rtl_sdr command line.

        Args:
            duration: capture length in seconds.

        Returns:
            The command as an argument list.
        """
        return [
            "rtl_sdr",
            "-f", str(self.frequency),
            "-s", str(self.sample_rate),
            "-g", self.gain,
            "-p", str(self.ppm),
            "-d", str(self.device_index),
            "-n", str(self.sample_rate * 2 * duration),
            "-",
        ]

    def require_sdr(self) -> bool:
        """Check that a dongle and rtl_sdr are available.

        Returns:
            True when a live capture is possible.
        """
        if shutil.which("rtl_sdr") is None:
            self.logger.error("rtl_sdr is not installed")
            self.logger.info("install it with: sudo pacman -S rtl-sdr")
            return False
        if not Hardware.sdr_devices():
            self.logger.error("no SDR device detected")
            self.logger.info("plug in the dongle, or replay a recording with --input FILE")
            return False
        return True

    def capture(self, duration: int, live: bool = False) -> int:
        """Capture from the dongle and decode every frame.

        Args:
            duration: capture seconds.
            live: render a live table while capturing.

        Returns:
            Process exit code.
        """
        command = self.rtl_command(duration)
        self.logger.info("capturing %.1f MHz for %ss at %.2f Msps",
                         self.frequency / 1e6, duration, self.sample_rate / 1e6)
        self.logger.debug("command: %s", " ".join(command))
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        except OSError as exc:
            self.logger.error("could not start rtl_sdr: %s", exc)
            return 1

        block_size = 262_144 * 2
        frames = 0
        started = time.time()
        self._install_signal_handlers()
        try:
            assert process.stdout is not None
            while self.running:
                block = process.stdout.read(block_size)
                if not block:
                    break
                decoded = self.demodulator.detect(block)
                for frame in decoded:
                    if self.handle_frame(frame):
                        frames += 1
                if live and self.aircraft:
                    self.render_live()
            process.wait(timeout=10)
        except KeyboardInterrupt:  # pragma: no cover - handled by signal
            pass
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    process.kill()
            if process.stderr is not None:
                error = process.stderr.read().decode(errors="replace").strip()
                if error and "error" in error.lower():
                    for line in error.splitlines()[:4]:
                        self.logger.warn("rtl_sdr: %s", line)
        elapsed = time.time() - started
        self.logger.ok("captured %ss, %d frame(s), %d aircraft",
                       f"{elapsed:.0f}", frames, len(self.aircraft))
        return 0

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers that stop the capture cleanly."""

        def stop(_signum: int, _frame: Any) -> None:
            self.running = False

        for name in ("SIGINT", "SIGTERM"):
            try:
                signal.signal(getattr(signal, name), stop)
            except (ValueError, OSError):  # pragma: no cover
                pass

    def read_iq_file(self, path: Path, live: bool = False) -> int:
        """Decode an IQ recording.

        Args:
            path: raw unsigned 8-bit IQ file (as written by ``rtl_sdr file.bin``).
            live: render the table as frames are decoded.

        Returns:
            Process exit code.
        """
        if not path.is_file():
            self.logger.error("no such IQ file: %s", path)
            return 1
        size = path.stat().st_size
        self.logger.info("decoding %s (%.1f MB)", path, size / 1e6)
        block_size = 1 << 18
        processed = 0
        frames = 0
        with path.open("rb") as handle:
            while True:
                block = handle.read(block_size)
                if not block:
                    break
                processed += len(block)
                for frame in self.demodulator.detect(block):
                    if self.handle_frame(frame):
                        frames += 1
                if live and self.aircraft:
                    self.render_live()
                if self.logger.level_name == "DEBUG" and processed % (8 << 18) == 0:
                    self.logger.debug("%.1f%% processed, %d aircraft",
                                      processed / max(1, size) * 100, len(self.aircraft))
        self.logger.ok("%d frame(s) from %d aircraft", frames, len(self.aircraft))
        return 0

    # -- decoding ---------------------------------------------------------- #
    def handle_frame(self, frame: bytes) -> bool:
        """Update the aircraft table from one validated frame.

        Args:
            frame: a raw Mode-S frame.

        Returns:
            True when the frame was understood.
        """
        parsed = ModeSDecoder.parse(frame)
        if parsed is None:
            return False
        icao = str(parsed.get("icao", "")).upper()
        if not icao or icao == "000000":
            return False
        record = self.aircraft.get(icao)
        if record is None:
            record = Aircraft(icao=icao)
            self.aircraft[icao] = record
            self.logger.info("new aircraft %s", icao)

        record.messages += 1
        record.last_seen = now_iso()
        record.frames.append(parsed.get("raw", ""))
        if len(record.frames) > 32:
            record.frames = record.frames[-32:]

        kind = parsed.get("kind", "")
        if parsed.get("callsign"):
            record.callsign = str(parsed["callsign"])
        if parsed.get("category"):
            record.category = str(parsed["category"])
        if parsed.get("altitude_ft") is not None:
            record.altitude_ft = int(parsed["altitude_ft"])
            record.altitude_source = str(parsed.get("altitude_source", ""))
        if parsed.get("ground_speed_kt") is not None:
            record.ground_speed_kt = float(parsed["ground_speed_kt"])
        if parsed.get("track_deg") is not None:
            record.track_deg = float(parsed["track_deg"])
        if parsed.get("vertical_rate_fpm") is not None:
            record.vertical_rate_fpm = int(parsed["vertical_rate_fpm"])
        if parsed.get("squawk"):
            record.squawk = str(parsed["squawk"])
        if parsed.get("emergency"):
            record.emergency = str(parsed["emergency"])
            if parsed["emergency"] not in ("no emergency", ""):
                self.logger.warn("%s reports: %s (squawk %s)", record.label,
                                 parsed["emergency"], record.squawk)
                self.record_event(record, f"emergency: {parsed['emergency']}", "HIGH")
        if parsed.get("on_ground") is not None:
            record.on_ground = bool(parsed["on_ground"])

        if kind in ("airborne_position", "surface_position"):
            record.position_messages += 1
            self._update_position(record, parsed, kind)
        return True

    def _update_position(self, record: Aircraft, parsed: Dict[str, Any],
                         kind: str) -> None:
        """Feed a position frame into the CPR pair and decode a fix.

        Args:
            record: the aircraft being tracked.
            parsed: the decoded frame.
            kind: ``airborne_position`` or ``surface_position``.
        """
        cpr = parsed.get("cpr")
        if cpr is None:
            return
        pair = (int(cpr), now_iso())
        if parsed.get("cpr_odd"):
            record.odd_position = pair
        else:
            record.even_position = pair
        if not (record.even_position and record.odd_position):
            return

        even_value, even_time = record.even_position
        odd_value, odd_time = record.odd_position
        # Global CPR needs both frames from within a short window
        if abs(seconds_between(even_time, odd_time)) > 12:
            return
        fix = decode_cpr_global(even_value, odd_value,
                                even_surface=kind == "surface_position",
                                odd_surface=kind == "surface_position")
        if not fix:
            return
        latitude, longitude = fix
        previous = (record.latitude, record.longitude)
        record.latitude, record.longitude = round(latitude, 6), round(longitude, 6)
        record.positions.append((record.latitude, record.longitude, now_iso()))
        if len(record.positions) > 500:
            record.positions = record.positions[-500:]
        if previous[0] is None:
            self.logger.ok("%s first fix: %.4f, %.4f", record.label,
                           record.latitude, record.longitude)
            self.record_event(record, f"first position fix {record.latitude:.4f},"
                                      f"{record.longitude:.4f}", "INFO")

    def record_event(self, record: Aircraft, message: str, severity: str) -> None:
        """Write an aircraft event to the shared database.

        Args:
            record: the aircraft.
            message: the event text.
            severity: INFO/HIGH/CRITICAL.
        """
        if self.database is None:
            return
        try:
            self.database.event("adsb_tracker", "aircraft",
                                f"{record.label}: {message}", severity,
                                data={"icao": record.icao, "callsign": record.callsign,
                                      "lat": record.latitude, "lon": record.longitude,
                                      "altitude_ft": record.altitude_ft})
        except Exception as exc:  # pragma: no cover
            self.logger.debug("event insert failed: %s", exc)

    def decode_hex(self, frames: Sequence[str]) -> int:
        """Decode hex frames supplied on the command line (debugging aid).

        Args:
            frames: hex strings, optionally comma separated.

        Returns:
            Process exit code: 0 when everything decoded, 1 when a frame failed.
        """
        failures = 0
        for entry in frames:
            for raw in entry.split(","):
                raw = raw.strip().replace(" ", "")
                if not raw:
                    continue
                try:
                    frame = bytes.fromhex(raw)
                except ValueError:
                    self.logger.error("not hex: %s", raw)
                    failures += 1
                    continue
                parsed = ModeSDecoder.parse(frame)
                if parsed is None:
                    self.logger.error("%s: CRC check failed or unsupported DF", raw)
                    failures += 1
                    continue
                self.handle_frame(frame)
                print(json.dumps(parsed, indent=2))
        return 1 if failures else 0

    # -- reporting --------------------------------------------------------- #
    def render_live(self) -> None:
        """Render the live aircraft table (Rich when available)."""
        rows = self.sorted_aircraft()
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.live import Live  # noqa: F401 - imported to guarantee rich works
        except ImportError:
            self.render_plain_table(rows)
            return

        console = Console()
        table = Table(title=f"ADS-B traffic · {len(rows)} aircraft · "
                            f"{self.demodulator.frame_count} frames",
                      header_style="bold magenta")
        for column in ("ICAO", "CALLSIGN", "ALT ft", "GS kt", "TRK", "V/S fpm",
                       "POSITION", "SQWK", "MSGS"):
            table.add_column(column, justify="right" if column not in
                             ("ICAO", "CALLSIGN", "POSITION") else "left")
        for aircraft in rows[:22]:
            table.add_row(
                aircraft.icao,
                aircraft.callsign.strip() or "—",
                format_altitude(aircraft.altitude_ft),
                format_number(aircraft.ground_speed_kt, 0),
                f"{aircraft.track_deg:.0f}°" if aircraft.track_deg is not None else "—",
                f"{aircraft.vertical_rate_fpm:+,}" if aircraft.vertical_rate_fpm else "—",
                aircraft.distance_sample,
                aircraft.squawk or "—",
                str(aircraft.messages),
            )
        console.clear()
        console.print(table)

    def render_plain_table(self, rows: Optional[List[Aircraft]] = None) -> None:
        """Render the aircraft table as plain text.

        Args:
            rows: aircraft to show (defaults to every aircraft, sorted).
        """
        rows = rows if rows is not None else self.sorted_aircraft()
        print()
        print(f"  {'ICAO':<8}{'CALLSIGN':<10}{'ALT':>8}{'GS':>7}{'TRK':>6}{'POSITION':>22}"
              f"{'SQWK':>7}{'MSGS':>6}")
        print("  " + "─" * 74)
        for aircraft in rows:
            position = (f"{aircraft.latitude:.3f},{aircraft.longitude:.3f}"
                        if aircraft.latitude is not None else "—")
            print(f"  {aircraft.icao:<8}{(aircraft.callsign.strip() or '—')[:8]:<10}"
                  f"{format_altitude(aircraft.altitude_ft):>8}"
                  f"{format_number(aircraft.ground_speed_kt, 0):>7}"
                  f"{format_number(aircraft.track_deg, 0):>5}°{position:>22}"
                  f"{aircraft.squawk or '—':>7}{aircraft.messages:>6}")
        print()

    def sorted_aircraft(self) -> List[Aircraft]:
        """Return aircraft sorted by how recently they were heard.

        Returns:
            The aircraft list.
        """
        return sorted(self.aircraft.values(), key=lambda item: item.last_seen,
                      reverse=True)

    def write_outputs(self, label: Optional[str] = None) -> Dict[str, Path]:
        """Write the JSON, CSV and KML outputs for this session.

        Args:
            label: optional name for the session files.

        Returns:
            A mapping of artefact name to path.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = label or datetime.now().strftime("%Y%m%d_%H%M%S")
        rows = self.sorted_aircraft()
        artefacts: Dict[str, Path] = {}

        summary = self.output_dir / f"aircraft_{stamp}.json"
        summary.write_text(json.dumps({
            "version": VERSION,
            "generated": now_iso(),
            "host": os.uname().nodename,
            "frequency_hz": self.frequency,
            "sample_rate": self.sample_rate,
            "frames": self.demodulator.frame_count,
            "aircraft_count": len(rows),
            "aircraft": [aircraft.as_dict() for aircraft in rows],
        }, indent=2) + "\n")
        artefacts["json"] = summary

        tracks = self.output_dir / f"tracks_{stamp}.csv"
        with tracks.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["icao", "callsign", "latitude", "longitude", "altitude_ft",
                             "ground_speed_kt", "track_deg", "vertical_rate_fpm",
                             "squawk", "last_seen"])
            for aircraft in rows:
                writer.writerow([aircraft.icao, aircraft.callsign.strip(),
                                 aircraft.latitude, aircraft.longitude,
                                 aircraft.altitude_ft, aircraft.ground_speed_kt,
                                 aircraft.track_deg, aircraft.vertical_rate_fpm,
                                 aircraft.squawk, aircraft.last_seen])
        artefacts["csv"] = tracks

        # A KML track file opens straight in Google Earth / QGIS for briefings
        kml = self.output_dir / f"tracks_{stamp}.kml"
        placemarks = []
        for aircraft in rows:
            if not aircraft.positions:
                continue
            coordinates = " ".join(f"{lon},{lat},0" for lat, lon, _ts in aircraft.positions)
            placemarks.append(
                "    <Placemark>\n"
                f"      <name>{escape_xml(aircraft.label)}</name>\n"
                "      <styleUrl>#track</styleUrl>\n"
                "      <LineString><altitudeMode>absolute</altitudeMode>"
                f"<coordinates>{coordinates}</coordinates></LineString>\n"
                "    </Placemark>")
        kml.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
            "  <Document>\n"
            f"    <name>cyberdeck ADS-B {stamp}</name>\n"
            "    <Style id=\"track\"><LineStyle><color>ff00ffff</color>"
            "<width>2</width></LineStyle></Style>\n"
            + "\n".join(placemarks) + "\n"
            "  </Document>\n</kml>\n")
        artefacts["kml"] = kml

        self.logger.ok("files written to %s", self.output_dir)
        return artefacts

    def summary_lines(self, limit: int = 12) -> List[str]:
        """Build the printable summary of the session.

        Args:
            limit: how many aircraft to list.

        Returns:
            Lines of text.
        """
        rows = self.sorted_aircraft()
        lines = [
            f"frames decoded : {self.demodulator.frame_count}",
            f"aircraft       : {len(rows)}",
        ]
        with_position = [aircraft for aircraft in rows
                         if aircraft.latitude is not None]
        lines.append(f"with a fix     : {len(with_position)}")
        if rows:
            lines.append("")
            lines.append(f"{'ICAO':<8}{'CALLSIGN':<10}{'ALT ft':>9}{'GS kt':>8}"
                         f"{'V/S':>8}  POSITION")
            for aircraft in rows[:limit]:
                position = (f"{aircraft.latitude:.4f},{aircraft.longitude:.4f}"
                            if aircraft.latitude is not None else "no fix")
                rate = (f"{aircraft.vertical_rate_fpm:+,}"
                        if aircraft.vertical_rate_fpm is not None else "—")
                lines.append(f"{aircraft.icao:<8}{(aircraft.callsign.strip() or '—')[:8]:<10}"
                             f"{format_altitude(aircraft.altitude_ft):>9}"
                             f"{format_number(aircraft.ground_speed_kt, 0):>8}"
                             f"{rate:>8}  {position}")
        return lines

    def close(self) -> None:
        """Close the database handle."""
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # pragma: no cover
                pass


def format_altitude(altitude: Optional[int]) -> str:
    """Format an altitude for a table, using an em dash when unknown.

    Args:
        altitude: altitude in feet, or None.

    Returns:
        The formatted string.
    """
    return f"{altitude:,}" if altitude is not None else "—"


def format_number(value: Optional[float], digits: int = 0) -> str:
    """Format a number for a table, using an em dash when unknown.

    Args:
        value: the number, or None.
        digits: decimal places to show.

    Returns:
        The formatted string.
    """
    if value is None:
        return "—"
    return f"{value:.{digits}f}"


def seconds_between(first_iso: str, second_iso: str) -> float:
    """Return the signed seconds between two ISO timestamps.

    Args:
        first_iso: earlier stamp.
        second_iso: later stamp.

    Returns:
        The difference in seconds, or 0.0 when unparseable.
    """
    try:
        first = datetime.fromisoformat(first_iso.replace("Z", ""))
        second = datetime.fromisoformat(second_iso.replace("Z", ""))
    except ValueError:
        return 0.0
    return (second - first).total_seconds()


def escape_xml(text: str) -> str:
    """Escape the five XML entities.

    Args:
        text: raw text.

    Returns:
        Escaped text.
    """
    for character, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                              ('"', "&quot;"), ("'", "&apos;")):
        text = text.replace(character, entity)
    return text


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="adsb_tracker.py",
        description="ADS-B / Mode-S aircraft tracker with a built-in decoder "
                    "(receive only)")
    parser.add_argument("--version", action="version", version=f"adsb_tracker {VERSION}")
    parser.add_argument("--duration", type=int, default=60,
                        help="capture seconds from the dongle (default: 60)")
    parser.add_argument("--input", type=Path, default=None,
                        help="decode a recorded IQ file instead of the dongle")
    parser.add_argument("--hex", action="append", default=[],
                        help="decode a hex frame from the command line (debugging)")
    parser.add_argument("--live", action="store_true",
                        help="redraw the live table while decoding")
    parser.add_argument("--write", action="store_true",
                        help="write JSON/CSV/KML outputs to captures/adsb/")
    parser.add_argument("--gain", default=None, help="tuner gain (dB or 'auto')")
    parser.add_argument("--ppm", type=int, default=None, help="frequency correction (ppm)")
    parser.add_argument("--device", type=int, default=None, help="SDR device index")
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the ADS-B tracker.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 success, 1 failure, 2 usage, 3 no SDR.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("adsb_tracker", level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("ADS-B tracker", f"v{VERSION} · 1090 MHz Mode-S")

    tracker = AdsbTracker(config, logger)
    if args.gain:
        tracker.gain = args.gain
    if args.ppm is not None:
        tracker.ppm = args.ppm
    if args.device is not None:
        tracker.device_index = args.device

    try:
        if args.hex:
            return tracker.decode_hex(args.hex)

        if args.input is not None:
            code = tracker.read_iq_file(args.input, live=args.live)
        else:
            if not tracker.require_sdr():
                logger.info("offline mode: ./adsb_tracker.py --input recording.iq")
                return 3
            code = tracker.capture(args.duration, live=args.live)

        if code == 0 and tracker.aircraft:
            if args.write:
                tracker.write_outputs()
            if args.json:
                print(json.dumps({
                    "version": VERSION,
                    "frames": tracker.demodulator.frame_count,
                    "aircraft": [aircraft.as_dict()
                                 for aircraft in tracker.sorted_aircraft()],
                }, indent=2))
            else:
                print()
                for line in tracker.summary_lines():
                    print("  " + line if line else "")
                print()
        elif code == 0:
            logger.warn("no ADS-B frames were decoded")
            logger.info("check the antenna and gain; 1090 MHz needs line of sight")
        return code
    finally:
        tracker.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
