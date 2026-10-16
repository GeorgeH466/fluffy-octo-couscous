#!/usr/bin/env python3
"""
sdr/tpms_monitor.py - tyre-pressure sensor monitor for 315/433.92/868 MHz.
==========================================================================

Description
-----------
Listens to TPMS (tyre pressure monitoring system) sensors, which broadcast
unencrypted OOK/ASK telegrams from inside each wheel roughly once a minute.
The telemetry is useful for two very different reasons:

* fleet checks - which tyres are soft, which sensor has gone quiet
* security - a sudden, unexplained pressure drop on a parked vehicle can mean
  someone is deflating a tyre, and a sensor ID that appears twice with different
  payloads (or from two locations) is a hint of a replayed or spoofed telegram

The module implements the demodulation itself:

* ``rtl_sdr`` capture (or replay of a recorded IQ file) at 315, 433.92 or 868 MHz
* OOK/ASK envelope demodulation with an adaptive threshold derived from the
  noise floor, and run-length extraction of the pulse train
* half-bit estimation from the pulse-width histogram, then conversion of pulses
  to Manchester cells
* Manchester decoding in the three variants used by TPMS chipsets (both
  polarities plus differential), ranked by how plausible the result is
* candidate telegram layouts: sensor ID, pressure (kPa), temperature (C), flags
  and checksum, reported with a confidence marker instead of a single guess
* a baseline per sensor in ``state/tpms_baseline.json`` so deviations raise
  alerts, plus packet logs under ``captures/tpms/``

Nothing is transmitted. Sensor IDs are hardware identifiers, not personal data,
but a TPMS survey of someone else's vehicle is still surveillance: only listen
to vehicles you are authorised to monitor.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: rtl-sdr (rtl_sdr, optional - an IQ file works without a dongle);
              optional: rich (live table)
Licence     : MIT - receive-only (see docs/LEGAL.md)

Usage
-----
    sudo ./tpms_monitor.py --duration 300 --live
    sudo ./tpms_monitor.py --frequency 315 --duration 600 --baseline
    ./tpms_monitor.py --input tpms_433.iq --json
    ./tpms_monitor.py --pulses pulses.txt      # decode a pulse-width capture
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import shutil
import signal
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
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

#: Frequencies TPMS uses around the world, in MHz
TPMS_BANDS = {
    315: "Americas / Japan (315 MHz)",
    433.92: "Europe / Asia (433.92 MHz)",
    868: "Europe (868 MHz, some OEM systems)",
}

#: Minimum interpretation score for a telegram to be reported. The scoring is
#: +2 for a matching checksum, +2 for a plausible pressure and +1 for a plausible
#: temperature, so the threshold means "checksum matched, or the geometry is
#: unambiguous without one".
ACCEPT_SCORE = 4

#: Candidate telegram layouts. Each entry maps a byte index to a meaning, so an
#: unknown sensor can still be interpreted by trying the plausible layouts.
LAYOUTS: Tuple[Dict[str, Any], ...] = (
    {"name": "schrader-8", "length": 8, "id": (0, 4), "pressure": 4, "temp": 5,
     "flags": 6, "checksum": 7, "pressure_scale": 2.75, "temp_offset": -50.0},
    {"name": "schrader-8-alt", "length": 8, "id": (0, 4), "pressure": 4, "temp": 5,
     "flags": 6, "checksum": 7, "pressure_scale": 2.5, "temp_offset": -40.0},
    {"name": "generic-9", "length": 9, "id": (1, 5), "pressure": 5, "temp": 6,
     "flags": 7, "checksum": 8, "pressure_scale": 2.75, "temp_offset": -50.0},
    {"name": "generic-10", "length": 10, "id": (0, 4), "pressure": 4, "pressure_hi": 5,
     "temp": 6, "flags": 7, "checksum": 9, "pressure_scale": 1.0,
     "temp_offset": -50.0},
    {"name": "autel-6", "length": 6, "id": (0, 4), "pressure": 4, "temp": 5,
     "checksum": None, "pressure_scale": 2.75, "temp_offset": -50.0},
)


# --------------------------------------------------------------------------- #
# Pulse-train demodulation
# --------------------------------------------------------------------------- #
@dataclass
class Pulse:
    """One run of a constant level in the demodulated envelope."""

    level: int
    microseconds: float

    def as_dict(self) -> Dict[str, Any]:
        """Return the pulse as a plain dictionary."""
        return {"level": self.level, "us": round(self.microseconds, 2)}


def envelope_trace(samples: Sequence[float], smoothing: int = 3) -> List[float]:
    """Build a smoothed envelope trace from demodulated samples.

    Args:
        samples: magnitude samples (>= 0).
        smoothing: moving-average window; a short window keeps the OOK edges sharp.

    Returns:
        The smoothed trace.
    """
    if smoothing <= 1:
        return list(samples)
    out: List[float] = []
    total = 0.0
    window: List[float] = []
    for value in samples:
        window.append(value)
        total += value
        if len(window) > smoothing:
            total -= window.pop(0)
        out.append(total / len(window))
    return out


def pulses_from_samples(samples: Sequence[float], sample_rate: int,
                        threshold_factor: float = 2.2) -> List[Pulse]:
    """Extract OOK pulses from a magnitude trace.

    The threshold is derived from the median of the trace, which is the noise
    floor whenever there is no transmission in the window; short runs are then
    filtered out so that noise does not produce a flood of one-sample pulses.

    Args:
        samples: magnitude samples.
        sample_rate: capture sample rate in Hz.
        threshold_factor: multiple of the noise floor that counts as "carrier on".

    Returns:
        The pulse list, in transmission order.
    """
    if not samples:
        return []
    trace = envelope_trace(samples)
    noise = statistics.median(trace)
    peak = max(trace)
    if peak <= 0 or peak < noise * 1.4:
        return []
    threshold = max(noise * threshold_factor, noise + (peak - noise) * 0.35)

    pulses: List[Pulse] = []
    current_level = 1 if trace[0] > threshold else 0
    run = 0
    for value in trace:
        level = 1 if value > threshold else 0
        if level == current_level:
            run += 1
            continue
        pulses.append(Pulse(current_level, run * 1e6 / sample_rate))
        current_level = level
        run = 1
    if run:
        pulses.append(Pulse(current_level, run * 1e6 / sample_rate))

    # Drop pulses so short that they cannot be signal (below a quarter of the
    # shortest plausible half-bit at 2 kbaud) and merge the gaps they leave
    minimum_us = 8.0
    cleaned: List[Pulse] = []
    for pulse in pulses:
        if pulse.microseconds >= minimum_us or (cleaned and cleaned[-1].level == pulse.level):
            if cleaned and cleaned[-1].level == pulse.level:
                cleaned[-1] = Pulse(pulse.level,
                                    cleaned[-1].microseconds + pulse.microseconds)
            else:
                cleaned.append(pulse)
    return cleaned


def parse_pulse_file(path: Path) -> List[Pulse]:
    """Read a pulse-width capture written by ``--dump-pulses``.

    The format is one pulse per line: ``<level> <microseconds>``, where level 1
    is carrier present. Lines starting with ``#`` are ignored.

    Args:
        path: the pulse file.

    Returns:
        The pulse list.
    """
    pulses: List[Pulse] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace(",", " ").split()
        if len(parts) < 2:
            continue
        try:
            level = int(float(parts[0]))
            duration = float(parts[1])
        except ValueError:
            continue
        pulses.append(Pulse(1 if level else 0, duration))
    return pulses


def estimate_half_bit(pulses: Sequence[Pulse], bitrate: Optional[float] = None) -> float:
    """Estimate the Manchester half-bit (cell) duration in microseconds.

    TPMS chipsets transmit between about 1.9 kbaud and 10 kbaud, so cells are
    between roughly 50 us and 260 us. The estimate uses the most common short
    pulse width, which is one cell.

    Args:
        pulses: the pulse train.
        bitrate: bit rate in bits per second, when it is already known.

    Returns:
        The cell duration in microseconds.
    """
    if bitrate:
        return 1e6 / (2.0 * bitrate)
    candidates = [pulse.microseconds for pulse in pulses if 20 <= pulse.microseconds <= 600]
    if not candidates:
        return 50.0
    rounded = Counter(round(value / 5.0) * 5 for value in candidates)
    cell = rounded.most_common(1)[0][0]
    # The most common pulse can be a full bit (two cells) for a stream of equal
    # bits; if it looks too long compared with the median, halve it.
    median = statistics.median(candidates)
    if cell > median * 1.6:
        cell = cell / 2.0
    return max(10.0, float(cell))


def pulses_to_cells(pulses: Sequence[Pulse], cell_us: float,
                    tolerance: float = 0.35) -> Optional[List[int]]:
    """Convert a pulse train into Manchester cells.

    Every pulse is quantised to the nearest whole number of cells. A few pulses
    will always be a little off because of receiver jitter, so up to a fifth of
    them may be clamped; a train that needs more clamping than that is not a
    Manchester telegram and ``None`` is returned.

    Args:
        pulses: the pulse train.
        cell_us: the cell duration in microseconds.
        tolerance: allowed relative error when quantising a pulse.

    Returns:
        A list of 0/1 cells, or ``None`` when the train does not quantise.
    """
    cells: List[int] = []
    clamped = 0
    for pulse in pulses:
        count = pulse.microseconds / cell_us
        rounded = max(1, int(round(count)))
        if rounded > 1 and abs(count - rounded) > tolerance * rounded:
            clamped += 1
            rounded = max(1, int(count))
        cells.extend([pulse.level] * rounded)
    if pulses and clamped > len(pulses) * 0.2:
        return None
    return cells


def find_preamble(cells: Sequence[int], minimum: int = 12) -> Optional[int]:
    """Find the alternating preamble that starts a TPMS telegram.

    Args:
        cells: the cell stream.
        minimum: how many alternating cells count as a preamble.

    Returns:
        The index of the first cell after the preamble, or ``None``.
    """
    run = 1
    for index in range(1, len(cells)):
        if cells[index] != cells[index - 1]:
            run += 1
        else:
            if run >= minimum:
                return index
            run = 1
    if run >= minimum:
        return len(cells)
    return None


def manchester_decode(cells: Sequence[int], polarity: int = 1,
                      differential: bool = False, initial: int = 0) -> Optional[List[int]]:
    """Decode Manchester cells into bits.

    Three variants cover every TPMS chipset seen in the field:

    * plain Manchester, rising edge = one symbol, falling edge = the other
    * the same inverted (``polarity`` = -1)
    * differential Manchester, where the data is carried by whether a
      transition happens at the bit boundary rather than in the middle

    Args:
        cells: the cell stream.
        polarity: 1 or -1, inverting the symbol mapping.
        differential: True for differential Manchester.
        initial: assumed level before the first cell (differential only).

    Returns:
        The bits decoded before the first invalid cell pair (which marks the end
        of the telegram), or ``None`` when there was nothing to decode. The
        caller decides whether a short result is noise or a real frame.
    """
    if len(cells) < 2:
        return None
    even = len(cells) - (len(cells) % 2)
    bits: List[int] = []
    previous = 1 if initial else 0
    for index in range(0, even, 2):
        first, second = cells[index], cells[index + 1]
        if first == second:
            # Every Manchester bit has a transition inside the bit period, so
            # two equal cells mean the telegram has ended (silence, or the next
            # burst of the same sensor). Stop here and keep what was decoded:
            # a run-length pulse train always has a tail of carrier-off cells.
            break
        if differential:
            transition_at_boundary = (first != previous)
            symbol = 0 if transition_at_boundary else 1
            bits.append(symbol if polarity > 0 else 1 - symbol)
            previous = second
        else:
            rising = (first == 0 and second == 1)
            bits.append(0 if rising == (polarity > 0) else 1)
            previous = second
    return bits or None


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Pack bits into bytes, most significant bit first.

    Args:
        bits: the bit list.

    Returns:
        The packed bytes (a trailing partial byte is dropped).
    """
    out = bytearray()
    for index in range(0, len(bits) - len(bits) % 8, 8):
        value = 0
        for bit in bits[index:index + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def checksum_sum8(payload: bytes) -> int:
    """Return the 8-bit sum checksum of a telegram body.

    Args:
        payload: the bytes to sum.

    Returns:
        The one-byte sum.
    """
    return sum(payload) & 0xFF


def checksum_xor8(payload: bytes) -> int:
    """Return the 8-bit XOR checksum of a telegram body.

    Args:
        payload: the bytes to sum.

    Returns:
        The one-byte XOR.
    """
    value = 0
    for byte in payload:
        value ^= byte
    return value


def plausible_pressure(kpa: Optional[float]) -> bool:
    """Return True when a pressure reading is physically plausible.

    Args:
        kpa: pressure in kilopascals.

    Returns:
        True for 120..500 kPa, the range a passenger-vehicle tyre covers.
    """
    return kpa is not None and 120.0 <= kpa <= 500.0


def plausible_temperature(celsius: Optional[float]) -> bool:
    """Return True when a temperature reading is plausible.

    Args:
        celsius: temperature in degrees Celsius.

    Returns:
        True for -40..125 C.
    """
    return celsius is not None and -40.0 <= celsius <= 125.0


def interpret_payload(payload: bytes, checksum_seed: int = 0) -> List[Dict[str, Any]]:
    """Interpret a telegram with every candidate layout.

    Args:
        payload: the telegram bytes (preamble already removed).
        checksum_seed: value used by some chipsets to seed the checksum.

    Returns:
        Candidate interpretations, most plausible first. Each dictionary has
        ``layout``, ``sensor_id``, ``pressure_kpa``, ``temperature_c``,
        ``checksum``, ``confidence`` and ``raw``.
    """
    candidates: List[Dict[str, Any]] = []
    for layout in LAYOUTS:
        if len(payload) < layout["length"]:
            continue
        body = payload[:layout["length"]]
        start, end = layout["id"]
        sensor_id = int.from_bytes(body[start:end], "big")
        pressure_byte = body[layout["pressure"]]
        pressure = pressure_byte * float(layout.get("pressure_scale", 2.75))
        if "pressure_hi" in layout:
            pressure = ((body[layout["pressure_hi"]] << 8) | pressure_byte) / 10.0
        temperature = body[layout["temp"]] + float(layout.get("temp_offset", -50.0))

        checksum_index = layout.get("checksum")
        checksum_state = "not present"
        if isinstance(checksum_index, int) and checksum_index < len(body):
            expected_sum = (checksum_sum8(body[:checksum_index]) + checksum_seed) & 0xFF
            expected_xor = (checksum_xor8(body[:checksum_index]) + checksum_seed) & 0xFF
            received = body[checksum_index]
            if received == expected_sum:
                checksum_state = "sum8 ok"
            elif received == expected_xor:
                checksum_state = "xor8 ok"
            else:
                checksum_state = "mismatch"

        score = 0
        if plausible_pressure(pressure):
            score += 2
        if plausible_temperature(temperature):
            score += 1
        if checksum_state.endswith("ok"):
            score += 2
        if sensor_id == 0 or sensor_id == 0xFFFFFFFF:
            score -= 2
        confidence = "high" if score >= 4 else ("medium" if score >= 2 else "low")

        candidates.append({
            "layout": layout["name"],
            "sensor_id": f"{sensor_id:08X}",
            "sensor_id_int": sensor_id,
            "pressure_kpa": round(pressure, 1),
            "pressure_psi": round(pressure * 0.145038, 1),
            "temperature_c": round(temperature, 1),
            "flags": body[layout["flags"]] if isinstance(layout.get("flags"), int) else None,
            "checksum": checksum_state,
            "confidence": confidence,
            "score": score,
            "raw": body.hex().upper(),
        })
    candidates.sort(key=lambda item: -item["score"])
    return candidates


@dataclass
class TpmsFrame:
    """One decoded TPMS telegram."""

    received: str
    frequency_hz: int
    bits: str
    payload: str
    sensor_id: str
    pressure_kpa: Optional[float]
    temperature_c: Optional[float]
    checksum: str
    layout: str
    confidence: str
    pulse_count: int
    cell_us: float
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """Return the frame as a plain dictionary."""
        return {
            "received": self.received,
            "frequency_hz": self.frequency_hz,
            "sensor_id": self.sensor_id,
            "pressure_kpa": self.pressure_kpa,
            "temperature_c": self.temperature_c,
            "checksum": self.checksum,
            "layout": self.layout,
            "confidence": self.confidence,
            "payload": self.payload,
            "bits": self.bits,
            "pulse_count": self.pulse_count,
            "cell_us": round(self.cell_us, 2),
            "candidates": self.candidates,
        }

    @property
    def display(self) -> str:
        """A one-line rendering of the telegram."""
        pressure = f"{self.pressure_kpa:.0f} kPa" if self.pressure_kpa is not None else "?"
        temperature = f"{self.temperature_c:.0f} C" if self.temperature_c is not None else "?"
        return (f"sensor {self.sensor_id} · {pressure} · {temperature} "
                f"· {self.layout} ({self.confidence}, {self.checksum})")


# --------------------------------------------------------------------------- #
# Monitor
# --------------------------------------------------------------------------- #
class TpmsMonitor:
    """Capture, decode and track TPMS telegrams.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
    """

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                               "/opt/cyberdeck-arsenal")))
        self.output_dir = self.install_dir / "captures" / "tpms"
        self.state_file = self.install_dir / "state" / "tpms_baseline.json"
        self.frequency = int(config.get("sdr.tpms_frequency_hz", 433_920_000))
        self.sample_rate = int(config.get("sdr.tpms_sample_rate", 250_000))
        self.gain = str(config.get("sdr.gain", "auto"))
        self.ppm = int(config.get("sdr.ppm", 0) or 0)
        self.device_index = int(config.get("sdr.device_index", 0) or 0)
        self.drop_threshold = float(config.get("sdr.tpms_pressure_drop_kpa", 30.0))
        self.frames: List[TpmsFrame] = []
        self.baseline: Dict[str, Any] = self.load_baseline()
        self.last_seen: Dict[str, TpmsFrame] = {}
        self.running = True
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)

    # -- baseline ---------------------------------------------------------- #
    def load_baseline(self) -> Dict[str, Any]:
        """Load the per-sensor baseline.

        Returns:
            A mapping of sensor id to its recorded readings.
        """
        if not self.state_file.is_file():
            return {}
        try:
            data = json.loads(self.state_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.warn("could not read the TPMS baseline: %s", exc)
            return {}
        return data if isinstance(data, dict) else {}

    def save_baseline(self) -> None:
        """Write the per-sensor baseline back to disk."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(self.baseline, indent=2) + "\n")
        try:
            self.state_file.chmod(0o600)
        except OSError:  # pragma: no cover
            pass
        self.logger.debug("baseline written to %s", self.state_file)

    # -- capture ----------------------------------------------------------- #
    def rtl_command(self, duration: int) -> List[str]:
        """Build the rtl_sdr command line.

        Args:
            duration: capture seconds.

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
            "-n", str(int(self.sample_rate * 2 * duration)),
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
        """Capture from the dongle and decode every telegram.

        Args:
            duration: capture seconds.
            live: render a live table while capturing.

        Returns:
            Process exit code.
        """
        command = self.rtl_command(duration)
        self.logger.info("listening on %.3f MHz for %ss at %.0f ksps",
                         self.frequency / 1e6, duration, self.sample_rate / 1e3)
        self.logger.debug("command: %s", " ".join(command))
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        except OSError as exc:
            self.logger.error("could not start rtl_sdr: %s", exc)
            return 1
        self._install_signal_handlers()
        started = time.time()
        try:
            assert process.stdout is not None
            self.consume_iq(process.stdout, duration=duration, live=live)
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
        self.logger.ok("captured %ss, %d telegram(s)", int(time.time() - started),
                       len(self.frames))
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

    def consume_iq(self, stream: Any, duration: int = 0, live: bool = False,
                   chunk: int = 1 << 17) -> int:
        """Read an IQ stream, demodulate it and decode telegrams.

        Args:
            stream: a file-like object returning raw unsigned 8-bit IQ bytes.
            duration: stop after this many seconds (0 = until the stream ends).
            live: render a live table as telegrams arrive.
            chunk: read size in bytes.

        Returns:
            The number of telegrams decoded.
        """
        before = len(self.frames)
        started = time.time()
        buffer = b""
        # TPMS telegrams last a few milliseconds: look for a gap of quiet in the
        # envelope, then decode the block that just ended.
        quiet_samples = 0
        block: List[float] = []
        while self.running:
            if duration and time.time() - started > duration:
                break
            data = stream.read(chunk)
            if not data:
                break
            buffer += data
            usable = len(buffer) - (len(buffer) % 2)
            block.extend(magnitudes(buffer[:usable]))
            buffer = buffer[usable:]

            noise = statistics.median(block[-4000:]) if len(block) > 4000 else 0.0
            tail = block[-64:]
            if noise and tail and max(tail) < noise * 1.6:
                quiet_samples += 64
            else:
                quiet_samples = 0
            if quiet_samples >= self.sample_rate // 50 and len(block) > 2000:
                self.decode_block(block, live=live)
                block = block[-2000:]
                quiet_samples = 0
        if block:
            self.decode_block(block, live=live)
        return len(self.frames) - before

    def read_iq_file(self, path: Path, live: bool = False) -> int:
        """Decode a recorded IQ file.

        Args:
            path: raw unsigned 8-bit IQ.
            live: render a live table as telegrams arrive.

        Returns:
            Process exit code.
        """
        if not path.is_file():
            self.logger.error("no such IQ file: %s", path)
            return 1
        self.logger.info("decoding %s (%.1f MB)", path, path.stat().st_size / 1e6)
        with path.open("rb") as handle:
            decoded = self.consume_iq(handle, duration=0, live=live)
        self.logger.ok("%d telegram(s) decoded", decoded)
        return 0

    # -- decoding ---------------------------------------------------------- #
    def decode_block(self, block: Sequence[float], live: bool = False) -> List[TpmsFrame]:
        """Decode every telegram present in a block of magnitude samples.

        Args:
            block: the magnitude samples.
            live: render a live table for each telegram.

        Returns:
            The decoded telegrams.
        """
        pulses = pulses_from_samples(block, self.sample_rate)
        return self.decode_pulses(pulses, live=live)

    def decode_pulses(self, pulses: Sequence[Pulse], live: bool = False,
                      bitrate: Optional[float] = None) -> List[TpmsFrame]:
        """Decode telegrams from a pulse train.

        Finding the preamble is not enough to know where the payload starts: the
        alternating pattern usually runs a few cells into the data, so the
        decoder also sweeps the alignment around the end of the preamble. For
        every alignment and every decoding variant (plain Manchester in both
        polarities, plus differential Manchester with either initial level) the
        payload is interpreted with every candidate layout, and the result with
        the best score wins. A telegram is only reported when its score reaches
        the acceptance threshold, which in practice means its checksum matched
        (checksum-less layouts are reported as low confidence and dropped).

        Args:
            pulses: the pulse train.
            live: render a live table for the telegram.
            bitrate: known bit rate, when it is already known.

        Returns:
            The decoded telegrams (at most one per burst - TPMS sensors repeat
            the same telegram several times in a few milliseconds).
        """
        if len(pulses) < 20:
            return []
        cell_us = estimate_half_bit(pulses, bitrate)
        cells = pulses_to_cells(pulses, cell_us)
        if not cells or len(cells) < 64:
            return []

        preamble_end = find_preamble(cells)
        if preamble_end is None:
            # No preamble at all: still sweep the first part of the block, a
            # clipped recording may have lost the alternating cells.
            offsets = list(range(0, min(len(cells) - 48, 24)))
            self.logger.debug("no preamble found - sweeping %d offsets", len(offsets))
        else:
            low = max(0, preamble_end - 24)
            high = min(len(cells) - 48, preamble_end + 33)
            offsets = list(range(low, max(low + 1, high)))

        best_frame: Optional[TpmsFrame] = None
        best_score = ACCEPT_SCORE - 1
        for offset in offsets:
            body_cells = cells[offset:]
            if len(body_cells) < 48:
                continue
            for polarity in (1, -1):
                for differential in (False, True):
                    for initial in ((0, 1) if differential else (0,)):
                        bits = manchester_decode(body_cells, polarity, differential,
                                                 initial)
                        if not bits or len(bits) < 48:
                            continue
                        payload = bits_to_bytes(bits)
                        if len(payload) < 5:
                            continue
                        candidates = interpret_payload(payload)
                        if not candidates:
                            continue
                        leader = candidates[0]
                        if leader["score"] <= best_score:
                            continue
                        best_score = leader["score"]
                        best_frame = TpmsFrame(
                            received=now_iso(),
                            frequency_hz=self.frequency,
                            bits="".join(str(bit) for bit in bits[:120]),
                            payload=payload.hex().upper(),
                            sensor_id=leader["sensor_id"],
                            pressure_kpa=leader["pressure_kpa"],
                            temperature_c=leader["temperature_c"],
                            checksum=leader["checksum"],
                            layout=leader["layout"],
                            confidence=leader["confidence"],
                            pulse_count=len(pulses),
                            cell_us=cell_us,
                            candidates=candidates[:3],
                        )

        if best_frame is None:
            self.logger.debug("no plausible telegram in %d pulse(s) (cell %.1f us)",
                              len(pulses), cell_us)
            return []
        self.handle_frame(best_frame, live=live)
        return [best_frame]

    def read_pulse_file(self, path: Path) -> int:
        """Decode a recorded pulse-width file.

        Args:
            path: the pulse file written by ``--dump-pulses``.

        Returns:
            Process exit code.
        """
        if not path.is_file():
            self.logger.error("no such pulse file: %s", path)
            return 1
        pulses = parse_pulse_file(path)
        if not pulses:
            self.logger.error("%s contains no pulses", path)
            return 1
        self.logger.info("%d pulse(s) in %s", len(pulses), path)
        frames = self.decode_pulses(pulses)
        if not frames:
            cell = estimate_half_bit(pulses)
            self.logger.warn("no telegram decoded (estimated cell %.1f us)", cell)
            self.logger.info("check the capture: try --bitrate or a cleaner recording")
            return 1
        return 0

    def dump_pulses(self, path: Path) -> int:
        """Dump the pulse train of the current capture to a text file.

        Args:
            path: the file to write.

        Returns:
            Process exit code: 0 on success, 3 when there is no hardware.
        """
        if not self.require_sdr():
            return 3
        if shutil.which("rtl_sdr") is None:  # pragma: no cover - guarded above
            return 3
        command = self.rtl_command(5)
        self.logger.info("capturing 5s for a pulse dump")
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, timeout=60,
                                    check=False).stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.logger.error("capture failed: %s", exc)
            return 1
        pulses = pulses_from_samples(magnitudes(output), self.sample_rate)
        path.write_text("# level(1=carrier) duration_microseconds\n" +
                        "\n".join(f"{pulse.level} {pulse.microseconds:.2f}"
                                  for pulse in pulses) + "\n")
        self.logger.ok("%d pulse(s) written to %s", len(pulses), path)
        return 0

    # -- tracking and alerts ----------------------------------------------- #
    def handle_frame(self, frame: TpmsFrame, live: bool = False) -> None:
        """Record a telegram, compare it with the baseline and alert.

        Args:
            frame: the decoded telegram.
            live: redraw the live table when True.
        """
        self.frames.append(frame)
        self.logger.ok("%s", frame.display)

        record = self.baseline.get(frame.sensor_id)
        if record is None:
            self.baseline[frame.sensor_id] = {
                "first_seen": frame.received,
                "last_seen": frame.received,
                "readings": 1,
                "pressure_kpa": frame.pressure_kpa,
                "temperature_c": frame.temperature_c,
                "min_pressure_kpa": frame.pressure_kpa,
                "max_pressure_kpa": frame.pressure_kpa,
                "layout": frame.layout,
            }
            self.logger.info("new sensor %s - added to the baseline", frame.sensor_id)
        else:
            record["last_seen"] = frame.received
            record["readings"] = int(record.get("readings", 0)) + 1
            previous = record.get("pressure_kpa")
            if frame.pressure_kpa is not None:
                record["pressure_kpa"] = frame.pressure_kpa
                record["min_pressure_kpa"] = min(
                    value for value in (record.get("min_pressure_kpa"),
                                        frame.pressure_kpa) if value is not None)
                record["max_pressure_kpa"] = max(
                    value for value in (record.get("max_pressure_kpa"),
                                        frame.pressure_kpa) if value is not None)
                if previous is not None:
                    drop = previous - frame.pressure_kpa
                    if drop >= self.drop_threshold:
                        self.alert(frame, f"pressure dropped {drop:.0f} kPa "
                                          f"({previous:.0f} -> {frame.pressure_kpa:.0f} kPa)",
                                   "HIGH")
                    elif drop <= -self.drop_threshold:
                        self.alert(frame, f"pressure rose {-drop:.0f} kPa "
                                          f"({previous:.0f} -> {frame.pressure_kpa:.0f} kPa)",
                                   "INFO")
            if frame.temperature_c is not None:
                record["temperature_c"] = frame.temperature_c
            record["layout"] = frame.layout

        # Two different payloads from the same sensor inside one second: sensors
        # do repeat their telegram, so identical repeats are expected, but a
        # changing payload is not.
        previous_frame = self.last_seen.get(frame.sensor_id)
        if previous_frame is not None:
            if previous_frame.payload != frame.payload:
                delta = abs(seconds_between(previous_frame.received, frame.received))
                if delta < 1.0:
                    self.alert(frame, "sensor id repeated with a different payload "
                                      f"within {delta:.2f}s - possible replay", "HIGH")
        self.last_seen[frame.sensor_id] = frame
        if live:
            self.render_live()

    def alert(self, frame: TpmsFrame, message: str, severity: str) -> None:
        """Record an alert for a sensor.

        Args:
            frame: the telegram that triggered it.
            message: the alert text.
            severity: INFO/HIGH/CRITICAL.
        """
        self.logger.warn("sensor %s: %s", frame.sensor_id, message)
        if self.database is None:
            return
        try:
            self.database.event("tpms_monitor", "tpms",
                                f"sensor {frame.sensor_id}: {message}", severity,
                                data=frame.as_dict())
        except Exception as exc:  # pragma: no cover
            self.logger.debug("event insert failed: %s", exc)

    # -- reporting --------------------------------------------------------- #
    def render_live(self, limit: int = 18) -> None:
        """Render the live table of telegrams (Rich when available).

        Args:
            limit: how many telegrams to show.
        """
        recent = self.frames[-limit:]
        try:
            from rich.console import Console
            from rich.table import Table
        except ImportError:
            self.render_plain_table(recent)
            return
        console = Console()
        table = Table(title=f"TPMS · {self.frequency / 1e6:.3f} MHz · "
                            f"{len(self.frames)} telegram(s)",
                      header_style="bold green")
        for column in ("TIME", "SENSOR", "PRESSURE", "TEMP", "LAYOUT", "CONF",
                       "CHECKSUM", "PAYLOAD"):
            table.add_column(column)
        for frame in recent:
            table.add_row(frame.received[11:19], frame.sensor_id,
                          f"{frame.pressure_kpa:.0f} kPa"
                          if frame.pressure_kpa is not None else "—",
                          f"{frame.temperature_c:.0f} C"
                          if frame.temperature_c is not None else "—",
                          frame.layout, frame.confidence, frame.checksum,
                          frame.payload[:20])
        console.clear()
        console.print(table)

    def render_plain_table(self, rows: Optional[Sequence[TpmsFrame]] = None) -> None:
        """Render telegrams as plain text.

        Args:
            rows: telegrams to show (defaults to the last 25).
        """
        rows = rows if rows is not None else self.frames[-25:]
        print()
        print(f"  {'TIME':<10}{'SENSOR':<10}{'PRESSURE':>11}{'TEMP':>8}  "
              f"{'LAYOUT':<16}{'CONF':<8}{'PAYLOAD'}")
        print("  " + "─" * 92)
        for frame in rows:
            pressure = (f"{frame.pressure_kpa:.0f} kPa"
                        if frame.pressure_kpa is not None else "—")
            temperature = (f"{frame.temperature_c:.0f} C"
                           if frame.temperature_c is not None else "—")
            print(f"  {frame.received[11:19]:<10}{frame.sensor_id:<10}"
                  f"{pressure:>11}{temperature:>8}  {frame.layout:<16}"
                  f"{frame.confidence:<8}{frame.payload[:24]}")
        print()

    def summary(self) -> Dict[str, Any]:
        """Build the run summary.

        Returns:
            Counters and per-sensor statistics.
        """
        per_sensor: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"telegrams": 0})
        for frame in self.frames:
            entry = per_sensor[frame.sensor_id]
            entry["telegrams"] += 1
            entry["pressure_kpa"] = frame.pressure_kpa
            entry["temperature_c"] = frame.temperature_c
            entry["layout"] = frame.layout
            entry["confidence"] = frame.confidence
        return {
            "version": VERSION,
            "generated": now_iso(),
            "frequency_hz": self.frequency,
            "sample_rate": self.sample_rate,
            "telegrams": len(self.frames),
            "sensors": dict(per_sensor),
            "known_sensors": len(self.baseline),
            "pressure_drop_threshold_kpa": self.drop_threshold,
            "decoded": [frame.as_dict() for frame in self.frames],
        }

    def write_outputs(self, label: Optional[str] = None) -> Dict[str, Path]:
        """Write the JSONL, CSV and summary artefacts.

        Args:
            label: optional name for the run.

        Returns:
            A mapping of artefact name to path.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = label or datetime.now().strftime("%Y%m%d_%H%M%S")
        artefacts: Dict[str, Path] = {}

        jsonl = self.output_dir / f"telegrams_{stamp}.jsonl"
        with jsonl.open("w") as handle:
            for frame in self.frames:
                handle.write(json.dumps(frame.as_dict()) + "\n")
        artefacts["jsonl"] = jsonl

        csv_path = self.output_dir / f"telegrams_{stamp}.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["received", "sensor_id", "pressure_kpa", "temperature_c",
                             "layout", "confidence", "checksum", "payload", "cell_us"])
            for frame in self.frames:
                writer.writerow([frame.received, frame.sensor_id, frame.pressure_kpa,
                                 frame.temperature_c, frame.layout, frame.confidence,
                                 frame.checksum, frame.payload, round(frame.cell_us, 2)])
        artefacts["csv"] = csv_path

        summary = self.output_dir / f"summary_{stamp}.json"
        summary.write_text(json.dumps(self.summary(), indent=2) + "\n")
        artefacts["json"] = summary
        self.logger.ok("artefacts written to %s", self.output_dir)
        return artefacts

    def close(self) -> None:
        """Persist the baseline and close the database."""
        self.save_baseline()
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # pragma: no cover
                pass


def magnitudes(data: bytes) -> List[float]:
    """Convert unsigned 8-bit IQ bytes into magnitude samples.

    Args:
        data: interleaved I/Q bytes.

    Returns:
        One magnitude per complex sample.
    """
    values = list(data)
    out: List[float] = []
    for index in range(0, len(values) - 1, 2):
        i = values[index] - 128
        q = values[index + 1] - 128
        out.append(math.sqrt(i * i + q * q))
    return out


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


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="tpms_monitor.py",
        description="TPMS tyre-pressure sensor monitor (receive only)",
        epilog=f"bands: {', '.join(f'{band} MHz' for band in TPMS_BANDS)}")
    parser.add_argument("--version", action="version", version=f"tpms_monitor {VERSION}")
    parser.add_argument("--frequency", type=float, default=None,
                        help="centre frequency in MHz (315, 433.92 or 868)")
    parser.add_argument("--duration", type=int, default=300,
                        help="capture seconds (default: 300 - TPMS is slow)")
    parser.add_argument("--input", type=Path, default=None,
                        help="decode a recorded IQ file")
    parser.add_argument("--pulses", type=Path, default=None,
                        help="decode a pulse-width file (level microseconds per line)")
    parser.add_argument("--dump-pulses", type=Path, default=None,
                        help="capture 5s and write the pulse train to a file")
    parser.add_argument("--bitrate", type=float, default=None,
                        help="known bit rate in bits/s (skips the auto estimate)")
    parser.add_argument("--sample-rate", type=int, default=None,
                        help="capture sample rate (default: from cyberdeck.conf)")
    parser.add_argument("--gain", default=None, help="tuner gain (dB or 'auto')")
    parser.add_argument("--live", action="store_true", help="redraw the table as telegrams arrive")
    parser.add_argument("--baseline", action="store_true",
                        help="update state/tpms_baseline.json from this run")
    parser.add_argument("--write", action="store_true",
                        help="write JSONL/CSV artefacts under captures/tpms/")
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the TPMS monitor.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 success, 1 failure, 3 no SDR.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("tpms_monitor", level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("TPMS monitor", f"v{VERSION} · 315/433.92/868 MHz")

    monitor = TpmsMonitor(config, logger)
    if args.frequency:
        monitor.frequency = int(args.frequency * 1e6)
    if args.sample_rate:
        monitor.sample_rate = args.sample_rate
    if args.gain:
        monitor.gain = args.gain

    try:
        if args.dump_pulses is not None:
            return monitor.dump_pulses(args.dump_pulses)
        if args.pulses is not None:
            code = monitor.read_pulse_file(args.pulses)
        elif args.input is not None:
            code = monitor.read_iq_file(args.input, live=args.live)
        else:
            if not monitor.require_sdr():
                logger.info("offline mode: ./tpms_monitor.py --input recording.iq")
                return 3
            code = monitor.capture(args.duration, live=args.live)

        if code == 0 and monitor.frames:
            if args.write:
                monitor.write_outputs()
            if args.baseline or args.write:
                monitor.save_baseline()
            if args.json:
                print(json.dumps(monitor.summary(), indent=2))
            else:
                monitor.render_plain_table()
                logger.info("%d telegram(s) from %d sensor(s)",
                            len(monitor.frames), len(monitor.summary()["sensors"]))
                logger.info("baseline: %s", monitor.state_file)
        elif code == 0:
            logger.warn("no TPMS telegrams decoded")
            logger.info("sensors transmit about once a minute - capture for longer, "
                        "and check the band for your region")
        return code
    finally:
        monitor.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
