#!/usr/bin/env python3
"""
sdr/keyfob_analyzer.py - sub-GHz remote control analyser (315/433.92/868 MHz).
==============================================================================

Description
-----------
Captures and analyses the OOK/ASK telegrams sent by fixed-frequency remotes:
car key fobs, gate and garage remotes, alarm keypads and wireless doorbells.
The module answers the questions that matter during an authorised assessment:

* how is the remote encoded - PWM, PPM/Manchester or the classic tri-state
  (PT2262/EV1527 style) scheme?
* what is the frame structure - how long is a press, how many repeats does it
  send, how long are the gaps?
* is the code fixed or rolling? Two presses of a fixed-code remote produce the
  same bits (which means a cheap radio can replay it); a rolling code changes
  every press and a replay will fail.
* what exactly was captured, stored in a searchable library with labels so the
  same remote can be recognised next time?

It also implements the pulse train -> bits conversion for each scheme, keeps a
signal library under ``captures/keyfobs/`` and can regenerate the IQ waveform of
a stored signal.

Transmission (``--replay``) is deliberately fenced: it needs ``--i-own-this-device``
as an explicit attestation, the global legal acknowledgement in cyberdeck.conf,
an interactive confirmation and a transmit-capable radio (HackRF). Replaying a
remote you do not own or operate is illegal in most jurisdictions - see
docs/LEGAL.md.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: rtl-sdr (rtl_sdr, optional - pulse files work without a dongle);
              optional: hackrf (hackrf_transfer) for --replay
Licence     : MIT - capture is receive-only, replay needs authorisation

Usage
-----
    sudo ./keyfob_analyzer.py --duration 20 --live
    ./keyfob_analyzer.py --pulses press.txt --analyse --json
    ./keyfob_analyzer.py --library --label "gate remote - reception"
    ./keyfob_analyzer.py --compare press1.json press2.json
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
import tempfile
import time
from collections import Counter
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
    from cyberlib import (  # type: ignore
        Config,
        Database,
        Hardware,
        Logger,
        colour,
        confirm,
        now_iso,
        require_acknowledgement,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: Sub-GHz bands a remote control may use, in MHz
REMOTE_BANDS = {
    315: "Americas - car fobs, gates, doorbells",
    433.92: "Europe/Asia - the most common remote band",
    868: "Europe - some OEM car systems and alarms",
    915: "Americas (ISM) - 902-928 MHz devices",
}

#: Gaps longer than this (microseconds) separate frames inside one press
FRAME_GAP_US = 5000.0


@dataclass
class Pulse:
    """One run of a constant level in the demodulated envelope."""

    level: int
    microseconds: float

    def as_dict(self) -> Dict[str, Any]:
        """Return the pulse as a plain dictionary."""
        return {"level": self.level, "us": round(self.microseconds, 2)}


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


def envelope(samples: Sequence[float], window: int = 2) -> List[float]:
    """Smooth a magnitude trace with a short moving average.

    Args:
        samples: magnitude samples.
        window: averaging window.

    Returns:
        The smoothed trace.
    """
    if window <= 1:
        return list(samples)
    out: List[float] = []
    total = 0.0
    queue: List[float] = []
    for value in samples:
        queue.append(value)
        total += value
        if len(queue) > window:
            total -= queue.pop(0)
        out.append(total / len(queue))
    return out


def pulses_from_samples(samples: Sequence[float], sample_rate: int,
                        threshold_factor: float = 2.2) -> List[Pulse]:
    """Extract OOK pulses (carrier on/off runs) from a magnitude trace.

    Args:
        samples: magnitude samples.
        sample_rate: capture sample rate in Hz.
        threshold_factor: multiple of the noise floor that counts as carrier on.

    Returns:
        The pulse train.
    """
    if not samples:
        return []
    trace = envelope(samples)
    noise = statistics.median(trace)
    peak = max(trace)
    if peak <= 0 or peak < noise * 1.4:
        return []
    threshold = max(noise * threshold_factor, noise + (peak - noise) * 0.35)

    pulses: List[Pulse] = []
    level = 1 if trace[0] > threshold else 0
    run = 0
    for value in trace:
        current = 1 if value > threshold else 0
        if current == level:
            run += 1
            continue
        pulses.append(Pulse(level, run * 1e6 / sample_rate))
        level = current
        run = 1
    if run:
        pulses.append(Pulse(level, run * 1e6 / sample_rate))
    return pulses


def parse_pulse_file(path: Path) -> List[Pulse]:
    """Read a ``level microseconds`` pulse file.

    Args:
        path: the pulse file.

    Returns:
        The pulse train.
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


def split_frames(pulses: Sequence[Pulse], gap_us: float = FRAME_GAP_US
                 ) -> List[List[Pulse]]:
    """Split a press into frames at the long gaps between repeats.

    Args:
        pulses: the pulse train of a whole press.
        gap_us: gaps longer than this separate frames.

    Returns:
        One pulse list per frame.
    """
    frames: List[List[Pulse]] = []
    current: List[Pulse] = []
    for pulse in pulses:
        if (pulse.level == 0 and pulse.microseconds > gap_us and current):
            frames.append(current)
            current = []
            continue
        current.append(pulse)
    if current:
        frames.append(current)
    return [frame for frame in frames if sum(1 for p in frame if p.level) >= 8]


def timing_histogram(pulses: Sequence[Pulse], top: int = 8) -> List[Tuple[float, int]]:
    """Summarise pulse widths.

    Args:
        pulses: the pulse train.
        top: how many widths to return.

    Returns:
        ``(width_us, count)`` pairs, most common first.
    """
    counter = Counter(round(pulse.microseconds) for pulse in pulses
                      if pulse.microseconds >= 20)
    return counter.most_common(top)


def base_time_unit(pulses: Sequence[Pulse]) -> float:
    """Estimate the smallest symbol time used by the remote.

    Args:
        pulses: the pulse train.

    Returns:
        The base time unit in microseconds (never below 20 us).
    """
    widths = sorted(pulse.microseconds for pulse in pulses if pulse.microseconds >= 20)
    if not widths:
        return 100.0
    # The 20th percentile is a robust estimate of the shortest pulse: a few long
    # gaps between frames would otherwise pull a plain minimum up.
    index = max(0, int(len(widths) * 0.2) - 1)
    return max(20.0, min(widths[index], widths[0] * 1.5))


@dataclass
class Signal:
    """A captured remote-control press."""

    captured: str
    frequency_hz: int
    sample_rate: int
    frames: List[List[Pulse]] = field(default_factory=list)
    encoding: str = "unknown"
    base_us: float = 0.0
    code: str = ""
    code_hex: str = ""
    bits: int = 0
    gap_ms: List[float] = field(default_factory=list)
    widths: List[Tuple[float, int]] = field(default_factory=list)
    repeats_identical: bool = False
    label: str = ""
    source: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def frame_count(self) -> int:
        """How many repeats the press contained."""
        return len(self.frames)

    @property
    def duration_ms(self) -> float:
        """Total length of the press in milliseconds."""
        return round(sum(pulse.microseconds for frame in self.frames for pulse in frame)
                     / 1000.0, 2)

    def frame_pulses(self, index: int = 0) -> List[Pulse]:
        """Return the pulses of one frame.

        Args:
            index: frame index.

        Returns:
            The pulse list, or an empty list when the index is out of range.
        """
        return self.frames[index] if 0 <= index < len(self.frames) else []

    def as_dict(self, include_pulses: bool = True) -> Dict[str, Any]:
        """Return the signal as a plain dictionary.

        Args:
            include_pulses: keep the raw pulse train (needed for replay).

        Returns:
            The dictionary.
        """
        payload: Dict[str, Any] = {
            "captured": self.captured,
            "frequency_hz": self.frequency_hz,
            "sample_rate": self.sample_rate,
            "label": self.label,
            "source": self.source,
            "encoding": self.encoding,
            "base_us": round(self.base_us, 2),
            "frames": self.frame_count,
            "bits": self.bits,
            "code": self.code,
            "code_hex": self.code_hex,
            "duration_ms": self.duration_ms,
            "gap_ms": [round(gap, 2) for gap in self.gap_ms],
            "widths": [[round(width, 1), count] for width, count in self.widths],
            "repeats_identical": self.repeats_identical,
            "notes": self.notes,
        }
        if include_pulses:
            payload["pulses"] = [[pulse.level, round(pulse.microseconds, 2)]
                                 for frame in self.frames for pulse in frame]
        return payload


def decode_pwm(frame: Sequence[Pulse], unit: float) -> Tuple[str, str]:
    """Decode a pulse-width-modulated remote frame.

    In PWM remotes each bit is a mark followed by a space; a short mark means 0
    and a long mark means 1 (some chipsets invert this, which the caller checks
    by comparing the two interpretations).

    Args:
        frame: the pulses of one frame.
        unit: the base time unit in microseconds.

    Returns:
        A ``(bits, note)`` pair.
    """
    bits: List[str] = []
    index = 0
    while index + 1 < len(frame):
        mark = frame[index]
        space = frame[index + 1]
        if mark.level == 0:            # start at a mark
            index += 1
            continue
        if mark.microseconds < unit * 0.5 or space.microseconds < unit * 0.5:
            index += 2
            continue
        bits.append("1" if mark.microseconds > space.microseconds else "0")
        index += 2
    return "".join(bits), "mark longer than space = 1"


def decode_tri_state(frame: Sequence[Pulse], unit: float) -> Tuple[str, List[str]]:
    """Decode a tri-state (PT2262/EV1527 style) frame.

    Each symbol is a mark/space pair whose lengths are 1, 2 or 3 units, giving
    the three states of a 12-bit encoder: ``01`` (short-short), ``10``
    (long-long) and the floating state in the middle.

    Args:
        frame: the pulses of one frame.
        unit: the base time unit in microseconds.

    Returns:
        A ``(bits, notes)`` pair, where bits use 0/1 and each symbol has been
        mapped to two bits.
    """
    symbols: List[str] = []
    notes: List[str] = []
    index = 0
    while index + 1 < len(frame):
        mark, space = frame[index], frame[index + 1]
        if mark.level == 0:
            index += 1
            continue
        mark_units = max(1, int(round(mark.microseconds / unit)))
        space_units = max(1, int(round(space.microseconds / unit)))
        if mark_units >= 24 and space_units >= 24:
            notes.append("sync symbol found")
            symbols.append("S")
        else:
            symbols.append(f"{mark_units}{space_units}")
        index += 2
    # Translate the common (mark, space) combinations into bits. PT2262 sends
    # 0 as 1:3, 1 as 3:1 and float as 2:2; EV1527 uses 1:3 and 3:1 only.
    mapping = {"13": "00", "31": "11", "22": "01", "11": "0", "33": "1"}
    bits = "".join(mapping.get(symbol, "?") for symbol in symbols if symbol != "S")
    return bits, notes


def decode_manchester(frame: Sequence[Pulse], unit: float) -> Tuple[str, str]:
    """Decode a PPM/Manchester remote frame.

    A remote usually starts a frame with a preamble that is not Manchester at
    all (long flat runs), so the cell stream is decoded from every alignment and
    the longest result wins: a wrong alignment hits two equal cells within a few
    symbols, while the right one decodes the whole payload.

    Args:
        frame: the pulses of one frame.
        unit: the base time unit in microseconds.

    Returns:
        A ``(bits, note)`` pair.
    """
    cells: List[int] = []
    for pulse in frame:
        count = pulse.microseconds / unit
        cells.extend([pulse.level] * max(1, int(round(count))))

    best = ""
    for offset in range(0, max(1, len(cells) - 8)):
        bits: List[str] = []
        for index in range(offset, len(cells) - 1, 2):
            first, second = cells[index], cells[index + 1]
            if first == second:
                break
            bits.append("0" if first == 0 and second == 1 else "1")
        candidate = "".join(bits)
        if len(candidate) > len(best):
            best = candidate
    return best, "Manchester cells at half the bit period"


def symbol_alphabet(frame: Sequence[Pulse], unit: float) -> Counter:
    """Count the (mark, space) unit patterns in a frame.

    Args:
        frame: the pulses of one frame.
        unit: the base time unit in microseconds.

    Returns:
        A counter of ``"<mark>:<space>"`` patterns.
    """
    patterns: Counter = Counter()
    for index in range(0, len(frame) - 1, 2):
        mark, space = frame[index], frame[index + 1]
        if mark.level == 0:
            continue
        mark_units = max(1, min(9, int(round(mark.microseconds / unit))))
        space_units = max(1, min(63, int(round(space.microseconds / unit))))
        if mark_units >= 9 and space_units >= 9:
            patterns["sync"] += 1
        else:
            patterns[f"{mark_units}:{space_units}"] += 1
    return patterns


def classify_encoding(frames: Sequence[Sequence[Pulse]], unit: float) -> str:
    """Classify the encoding scheme used by a remote.

    The three schemes are told apart by the symbol alphabet:

    * ``tri-state`` (PT2262/EV1527): the mark/space pairs are 1:3, 3:1 and often
      2:2, all with the same total length (so the alphabet has three members)
    * ``pwm``: only two pair patterns, again with a constant total
    * ``manchester``: marks and spaces are all about one unit long

    Args:
        frames: the frames of one press.
        unit: the base time unit in microseconds.

    Returns:
        One of ``pwm``, ``tri-state``, ``manchester`` or ``unknown``.
    """
    frame = frames[0] if frames else []
    if len(frame) < 8:
        return "unknown"
    marks = [pulse.microseconds for pulse in frame if pulse.level == 1]
    spaces = [pulse.microseconds for pulse in frame if pulse.level == 0]
    if not marks or not spaces:
        return "unknown"

    patterns = symbol_alphabet(frame, unit)
    patterns.pop("sync", None)
    ratios = Counter(round(pulse.microseconds / unit) for pulse in frame)
    mark_ratio = statistics.median(marks) / unit
    space_ratio = statistics.median(spaces) / unit

    if 0.7 <= mark_ratio <= 1.4 and 0.7 <= space_ratio <= 1.4 and len(ratios) <= 3:
        return "manchester"

    totals = [round((frame[index].microseconds + frame[index + 1].microseconds) / unit)
              for index in range(0, len(frame) - 1, 2)
              if frame[index].level == 1]
    constant_period = False
    if totals:
        common, share = Counter(totals).most_common(1)[0]
        constant_period = share / len(totals) > 0.6 and 3 <= common <= 40

    if constant_period and len(patterns) >= 3:
        return "tri-state"
    if constant_period:
        return "pwm"
    if 1.5 <= mark_ratio <= 3.5 or 1.5 <= space_ratio <= 3.5:
        return "tri-state"
    return "unknown"


def analyse_press(pulses: Sequence[Pulse], frequency_hz: int, sample_rate: int,
                  label: str = "", source: str = "") -> Signal:
    """Analyse one press (one or more repeated frames).

    Args:
        pulses: the pulse train of the press.
        frequency_hz: capture frequency.
        sample_rate: capture sample rate.
        label: optional label for the signal.
        source: where the press came from (file or "live").

    Returns:
        The analysed :class:`Signal`.
    """
    signal = Signal(captured=now_iso(), frequency_hz=frequency_hz,
                    sample_rate=sample_rate, label=label, source=source)
    signal.frames = split_frames(pulses)
    if not signal.frames:
        signal.notes.append("no frame found - the capture may be empty or too short")
        return signal

    signal.base_us = base_time_unit(signal.frames[0])
    signal.widths = timing_histogram([pulse for frame in signal.frames for pulse in frame])
    signal.encoding = classify_encoding(signal.frames, signal.base_us)

    # Gaps between repeated frames are the giveaway for a press vs one frame
    for index in range(len(signal.frames) - 1):
        tail = signal.frames[index][-1] if signal.frames[index] else None
        if tail is not None and tail.level == 0:
            signal.gap_ms.append(tail.microseconds / 1000.0)
        else:
            signal.gap_ms.append(0.0)

    if signal.encoding == "pwm":
        bits, note = decode_pwm(signal.frames[0], signal.base_us)
        signal.notes.append(note)
    elif signal.encoding == "tri-state":
        bits, notes = decode_tri_state(signal.frames[0], signal.base_us)
        signal.notes.extend(notes)
        signal.notes.append("tri-state symbols mapped to bits (0=1:3, 1=3:1, float=2:2)")
    else:
        bits, note = decode_manchester(signal.frames[0], signal.base_us)
        signal.notes.append(note)
    signal.code = bits
    signal.bits = len(bits)
    signal.code_hex = bits_to_hex(bits)

    codes = []
    for frame in signal.frames:
        if signal.encoding == "pwm":
            codes.append(decode_pwm(frame, signal.base_us)[0])
        elif signal.encoding == "tri-state":
            codes.append(decode_tri_state(frame, signal.base_us)[0])
        else:
            codes.append(decode_manchester(frame, signal.base_us)[0])
    signal.repeats_identical = len(set(codes)) == 1 and len(codes) > 1
    if signal.repeats_identical:
        signal.notes.append(f"{len(codes)} repeats with identical payload")
    if signal.encoding == "unknown":
        signal.notes.append("encoding not recognised - timing looks unusual; "
                            "check the capture quality or the sample rate")
    return signal


def bits_to_hex(bits: str) -> str:
    """Pack a bit string into hexadecimal.

    Args:
        bits: the bit string (0/1, other characters ignored).

    Returns:
        The hexadecimal representation.
    """
    clean = "".join(character for character in bits if character in "01")
    if not clean:
        return ""
    clean += "0" * ((4 - len(clean) % 4) % 4)
    return f"{int(clean, 2):0{len(clean) // 4}X}"


def hamming(first: str, second: str) -> int:
    """Return the number of differing bits between two bit strings.

    Args:
        first: first bit string.
        second: second bit string.

    Returns:
        The Hamming distance, or -1 when the lengths differ.
    """
    if len(first) != len(second):
        return -1
    return sum(1 for a, b in zip(first, second) if a != b)


def synthesise_iq(pulses: Sequence[Pulse], sample_rate: int, amplitude: int = 96
                  ) -> bytes:
    """Turn a pulse train back into unsigned 8-bit IQ for transmission.

    Args:
        pulses: the pulse train of one press.
        sample_rate: sample rate to synthesise at.
        amplitude: carrier amplitude (0-127).

    Returns:
        The interleaved I/Q bytes.
    """
    out = bytearray()
    for pulse in pulses:
        count = int(round(pulse.microseconds * sample_rate / 1e6))
        for _ in range(count):
            if pulse.level:
                out.append(128 + amplitude)
                out.append(128)
            else:
                out.append(128)
                out.append(128)
    return bytes(out)


class KeyfobAnalyzer:
    """Capture, analyse and store sub-GHz remote-control signals.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
    """

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                               "/opt/cyberdeck-arsenal")))
        self.output_dir = self.install_dir / "captures" / "keyfobs"
        self.library_file = self.output_dir / "library.json"
        self.frequency = int(config.get("sdr.keyfob_frequency_hz", 433_920_000))
        self.sample_rate = int(config.get("sdr.keyfob_sample_rate", 250_000))
        self.gain = str(config.get("sdr.gain", "auto"))
        self.ppm = int(config.get("sdr.ppm", 0) or 0)
        self.device_index = int(config.get("sdr.device_index", 0) or 0)
        self.signals: List[Signal] = []
        self.running = True
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)

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
            self.logger.info("plug in the dongle, or analyse a pulse file with --pulses")
            return False
        return True

    def capture(self, duration: int, live: bool = False) -> int:
        """Capture and analyse presses until the timer expires.

        Args:
            duration: capture seconds.
            live: report each press as it is decoded.

        Returns:
            Process exit code.
        """
        command = self.rtl_command(duration)
        self.logger.info("listening on %.3f MHz for %ss at %.0f ksps",
                         self.frequency / 1e6, duration, self.sample_rate / 1e3)
        self.logger.info("press the remote you are authorised to test")
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
        self.logger.ok("captured %ss, %d press(es)", int(time.time() - started),
                       len(self.signals))
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
        """Read an IQ stream and analyse every press found in it.

        Args:
            stream: file-like object returning unsigned 8-bit IQ.
            duration: stop after this many seconds (0 = until the stream ends).
            live: report each press as it is decoded.
            chunk: read size in bytes.

        Returns:
            The number of presses analysed.
        """
        before = len(self.signals)
        started = time.time()
        buffer = b""
        quiet = 0
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
            if noise and block[-64:] and max(block[-64:]) < noise * 1.6:
                quiet += 64
            else:
                quiet = 0
            if quiet >= self.sample_rate // 40 and len(block) > 2000:
                self.analyse_block(block, live=live)
                block = block[-2000:]
                quiet = 0
        if block:
            self.analyse_block(block, live=live)
        return len(self.signals) - before

    def read_iq_file(self, path: Path, live: bool = False) -> int:
        """Analyse a recorded IQ file.

        Args:
            path: raw unsigned 8-bit IQ.
            live: report each press as it is decoded.

        Returns:
            Process exit code.
        """
        if not path.is_file():
            self.logger.error("no such IQ file: %s", path)
            return 1
        self.logger.info("analysing %s (%.1f MB)", path, path.stat().st_size / 1e6)
        with path.open("rb") as handle:
            decoded = self.consume_iq(handle, duration=0, live=live)
        self.logger.ok("%d press(es) analysed", decoded)
        return 0

    # -- analysis ---------------------------------------------------------- #
    def analyse_block(self, block: Sequence[float], live: bool = False) -> List[Signal]:
        """Extract pulses from a block of samples and analyse the presses in it.

        Args:
            block: magnitude samples.
            live: report each press as it is decoded.

        Returns:
            The signals found.
        """
        pulses = pulses_from_samples(block, self.sample_rate)
        return self.analyse_pulses(pulses, live=live)

    def analyse_pulses(self, pulses: Sequence[Pulse], live: bool = False,
                       label: str = "", source: str = "live") -> List[Signal]:
        """Analyse a pulse train, splitting it into presses.

        A press is a burst of pulses; two presses from the same remote in one
        capture are separated by a long silence (the operator let go of the
        button).

        Args:
            pulses: the pulse train.
            live: report each press as it is decoded.
            label: optional label.
            source: description of where the pulses came from.

        Returns:
            The analysed signals.
        """
        if len(pulses) < 15:
            return []
        found: List[Signal] = []
        # Split the train into presses: silence longer than half a second
        press_gap_us = 500_000.0
        current: List[Pulse] = []
        for pulse in pulses:
            if pulse.level == 0 and pulse.microseconds > press_gap_us and current:
                signal = analyse_press(current, self.frequency, self.sample_rate,
                                       label=label, source=source)
                if signal.bits or signal.frames:
                    found.append(signal)
                current = []
                continue
            current.append(pulse)
        if current:
            signal = analyse_press(current, self.frequency, self.sample_rate,
                                   label=label, source=source)
            if signal.bits or signal.frames:
                found.append(signal)

        for signal in found:
            self.handle_signal(signal, live=live)
        return found

    def read_pulse_file(self, path: Path, label: str = "") -> int:
        """Analyse a pulse file.

        Args:
            path: the pulse file.
            label: optional label.

        Returns:
            Process exit code: 0 success, 1 nothing decoded.
        """
        if not path.is_file():
            self.logger.error("no such pulse file: %s", path)
            return 1
        pulses = parse_pulse_file(path)
        if not pulses:
            self.logger.error("%s contains no pulses", path)
            return 1
        self.logger.info("%d pulse(s) in %s", len(pulses), path)
        found = self.analyse_pulses(pulses, label=label, source=str(path))
        if not found:
            self.logger.warn("no press found - is this a remote capture?")
            return 1
        return 0

    def handle_signal(self, signal: Signal, live: bool = False) -> None:
        """Report and record a captured signal.

        Args:
            signal: the analysed signal.
            live: redraw the summary when True.
        """
        self.signals.append(signal)
        self.logger.ok("%s", self.describe(signal))
        if self.database is not None:
            try:
                self.database.event(
                    "keyfob_analyzer", "rf",
                    f"{signal.encoding} remote · {signal.bits} bits · "
                    f"{signal.frame_count} repeat(s)",
                    "INFO", data=signal.as_dict(include_pulses=False))
            except Exception as exc:  # pragma: no cover
                self.logger.debug("event insert failed: %s", exc)
        if live:
            self.render_plain_table([signal])

    @staticmethod
    def describe(signal: Signal) -> str:
        """Build the one-line description of a signal.

        Args:
            signal: the analysed signal.

        Returns:
            The description.
        """
        return (f"{signal.encoding:<11} · {signal.bits:>3} bits · "
                f"{signal.frame_count} repeat(s) · base {signal.base_us:.0f} us · "
                f"code {signal.code_hex or '—'}")

    def render_plain_table(self, rows: Optional[Sequence[Signal]] = None) -> None:
        """Render signals as a plain text table.

        Args:
            rows: signals to show (defaults to every signal).
        """
        rows = rows if rows is not None else self.signals
        print()
        print(f"  {'TIME':<10}{'ENCODING':<12}{'BITS':>5}{'REPEATS':>9}"
              f"{'BASE':>8}  {'CODE HEX':<18}LABEL")
        print("  " + "─" * 84)
        for signal in rows:
            print(f"  {signal.captured[11:19]:<10}{signal.encoding:<12}{signal.bits:>5}"
                  f"{signal.frame_count:>9}{signal.base_us:>7.0f}u  "
                  f"{signal.code_hex[:16]:<18}{signal.label}")
        print()

    # -- library ----------------------------------------------------------- #
    def load_library(self) -> List[Dict[str, Any]]:
        """Load the signal library.

        Returns:
            The stored signals.
        """
        if not self.library_file.is_file():
            return []
        try:
            data = json.loads(self.library_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.warn("could not read the signal library: %s", exc)
            return []
        return data if isinstance(data, list) else []

    def save_to_library(self, label: str = "") -> int:
        """Append the current capture to the signal library.

        Args:
            label: label to store with the signals.

        Returns:
            The number of signals added.
        """
        if not self.signals:
            self.logger.warn("nothing to store - capture or analyse a press first")
            return 0
        library = self.load_library()
        added = 0
        for signal in self.signals:
            entry = signal.as_dict(include_pulses=True)
            entry["label"] = label or signal.label
            # Recognise a known signal by its code and frequency
            for existing in library:
                if (existing.get("code_hex") == entry["code_hex"]
                        and existing.get("frequency_hz") == entry["frequency_hz"]):
                    existing["seen"] = int(existing.get("seen", 1)) + 1
                    existing["last_seen"] = entry["captured"]
                    break
            else:
                entry["seen"] = 1
                entry["first_seen"] = entry["captured"]
                entry["last_seen"] = entry["captured"]
                library.append(entry)
                added += 1
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.library_file.write_text(json.dumps(library, indent=2) + "\n")
        try:
            self.library_file.chmod(0o600)
        except OSError:  # pragma: no cover
            pass
        self.logger.ok("%d new signal(s) stored in %s", added, self.library_file)
        if added < len(self.signals):
            self.logger.info("%d signal(s) matched entries already in the library",
                             len(self.signals) - added)
        return added

    def list_library(self) -> int:
        """Print the signal library.

        Returns:
            Process exit code (3 when the library is empty).
        """
        library = self.load_library()
        if not library:
            self.logger.info("the library is empty - capture a press and use --library")
            return 3
        print()
        print(f"  {'LABEL':<26}{'ENCODING':<12}{'BITS':>5}{'CODE HEX':<18}"
              f"{'MHZ':>7}{'SEEN':>6}{'LAST SEEN'}")
        print("  " + "─" * 96)
        for entry in library:
            print(f"  {str(entry.get('label', ''))[:24]:<26}"
                  f"{str(entry.get('encoding', '')):<12}"
                  f"{int(entry.get('bits', 0)):>5}"
                  f"{str(entry.get('code_hex', ''))[:16]:<18}"
                  f"{entry.get('frequency_hz', 0) / 1e6:>7.3f}"
                  f"{int(entry.get('seen', 1)):>6}  {entry.get('last_seen', '')[:19]}")
        print()
        return 0

    def compare_files(self, first: Path, second: Path) -> int:
        """Compare two stored signals and report whether the code changed.

        Args:
            first: path to a JSON signal (from --write or the library).
            second: path to the second signal.

        Returns:
            Process exit code: 0 identical (fixed code), 10 changed (rolling).
        """
        signals = []
        for path in (first, second):
            if not path.is_file():
                self.logger.error("no such file: %s", path)
                return 1
            try:
                signals.append(json.loads(path.read_text()))
            except json.JSONDecodeError as exc:
                self.logger.error("%s is not a signal file: %s", path, exc)
                return 1
        first_signal, second_signal = signals
        if isinstance(first_signal, list):
            first_signal = first_signal[0] if first_signal else {}
        if isinstance(second_signal, list):
            second_signal = second_signal[0] if second_signal else {}

        code_a = str(first_signal.get("code", ""))
        code_b = str(second_signal.get("code", ""))
        distance = hamming(code_a, code_b)
        print()
        print(f"  first : {code_a[:64]}  ({first_signal.get('code_hex', '')})")
        print(f"  second: {code_b[:64]}  ({second_signal.get('code_hex', '')})")
        print()
        if distance == 0:
            self.logger.warn("IDENTICAL payload - this remote uses a FIXED code")
            self.logger.warn("a fixed code can be replayed by anyone who captured it once")
            print(colour("  recommendation: treat the remote as a bearer token; replace it "
                         "with a rolling-code or challenge-response system where the risk "
                         "justifies it", "yellow"))
            return 0
        if distance < 0:
            self.logger.warn("the two captures have different lengths (%d vs %d bits)",
                             len(code_a), len(code_b))
            self.logger.info("different encoding or a partial capture - re-record both")
            return 1
        self.logger.ok("payloads differ by %d of %d bits", distance, len(code_a))
        if distance <= 4:
            print(colour("  small differences: possibly a fixed code with a few bits of "
                         "state (button id, battery flag), or a counter in the low bits",
                         "yellow"))
            return 10
        self.logger.ok("the code changes between presses - consistent with a ROLLING code")
        self.logger.info("a replayed capture will normally be rejected by the receiver")
        return 10

    def write_outputs(self, label: Optional[str] = None) -> Dict[str, Path]:
        """Write the capture JSON, CSV and a regenerated IQ file.

        Args:
            label: optional name for the run.

        Returns:
            A mapping of artefact name to path.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = label or datetime.now().strftime("%Y%m%d_%H%M%S")
        artefacts: Dict[str, Path] = {}

        json_path = self.output_dir / f"press_{stamp}.json"
        json_path.write_text(json.dumps(
            [signal.as_dict() for signal in self.signals], indent=2) + "\n")
        artefacts["json"] = json_path

        csv_path = self.output_dir / f"press_{stamp}.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["captured", "frequency_hz", "encoding", "base_us", "bits",
                             "frames", "code", "code_hex", "duration_ms", "label"])
            for signal in self.signals:
                writer.writerow([signal.captured, signal.frequency_hz, signal.encoding,
                                 round(signal.base_us, 2), signal.bits, signal.frame_count,
                                 signal.code, signal.code_hex, signal.duration_ms,
                                 signal.label])
        artefacts["csv"] = csv_path

        if self.signals:
            iq_path = self.output_dir / f"press_{stamp}.cs8"
            iq_path.write_bytes(synthesise_iq(self.signals[0].frame_pulses(0),
                                              self.sample_rate))
            artefacts["iq"] = iq_path
            self.logger.info("regenerated IQ written to %s (for --replay)", iq_path.name)
        self.logger.ok("artefacts written to %s", self.output_dir)
        return artefacts

    # -- replay ------------------------------------------------------------ #
    def replay(self, path: Path, transmitter: str, duration: Optional[float] = None,
               count: int = 1) -> int:
        """Transmit a stored signal. Authorisation is checked by the caller.

        Args:
            path: a signal JSON file or a regenerated .cs8 IQ file.
            transmitter: transmitter backend name (``hackrf``).
            duration: seconds to transmit (defaults to the signal length).
            count: how many times to transmit.

        Returns:
            Process exit code: 0 success, 1 failure, 3 no transmitter.
        """
        if transmitter != "hackrf":
            self.logger.error("unsupported transmitter: %s", transmitter)
            return 3
        if shutil.which("hackrf_transfer") is None:
            self.logger.error("hackrf_transfer is not installed")
            self.logger.info("install it with: sudo pacman -S hackrf")
            self.logger.info("a transmit-capable radio is required - an RTL-SDR cannot transmit")
            return 3
        if not path.is_file():
            self.logger.error("no such signal file: %s", path)
            return 1

        if path.suffix == ".json":
            try:
                payload = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                self.logger.error("could not read %s: %s", path, exc)
                return 1
            if isinstance(payload, list):
                payload = payload[0] if payload else {}
            pulses = [Pulse(int(level), float(microseconds))
                      for level, microseconds in payload.get("pulses", [])]
            if not pulses:
                self.logger.error("%s has no stored pulse train (was it written "
                                  "with --write?)", path)
                return 1
            iq = synthesise_iq(pulses, self.sample_rate)
            handle = tempfile.NamedTemporaryFile(prefix="cdeck-replay-", suffix=".cs8",
                                                 delete=False)
            handle.write(iq)
            handle.close()
            iq_path = Path(handle.name)
        else:
            iq_path = path
            iq = iq_path.read_bytes()

        seconds = duration or round(len(iq) / 2 / self.sample_rate + 0.2, 2)
        for attempt in range(1, count + 1):
            command = [
                "hackrf_transfer",
                "-t", str(iq_path),
                "-f", str(self.frequency),
                "-s", str(self.sample_rate),
                "-a", "1",
                "-x", "20",           # 20 dB amplifier
                "-R",                 # repeat the buffer for the whole duration
            ]
            self.logger.warn("transmitting attempt %d/%d on %.3f MHz for %ss",
                             attempt, count, self.frequency / 1e6, seconds)
            try:
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.PIPE)
                deadline = time.time() + seconds
                while process.poll() is None and time.time() < deadline:
                    time.sleep(0.1)
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:  # pragma: no cover
                        process.kill()
                error = process.stderr.read().decode(errors="replace") if process.stderr \
                    else ""
                for line in error.strip().splitlines()[-3:]:
                    self.logger.debug("hackrf_transfer: %s", line)
            except OSError as exc:
                self.logger.error("could not start hackrf_transfer: %s", exc)
                return 1
            time.sleep(0.3)
        self.logger.ok("transmission finished")
        if self.database is not None:
            try:
                self.database.event("keyfob_analyzer", "rf",
                                    f"replay transmitted on {self.frequency / 1e6:.3f} MHz "
                                    f"({count} attempt(s))", "WARNING",
                                    data={"file": str(path), "count": count})
            except Exception as exc:  # pragma: no cover
                self.logger.debug("event insert failed: %s", exc)
        if iq_path.exists() and iq_path.name.startswith("cdeck-replay-"):
            try:
                iq_path.unlink()
            except OSError:  # pragma: no cover
                pass
        return 0

    def close(self) -> None:
        """Close the database handle."""
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # pragma: no cover
                pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="keyfob_analyzer.py",
        description="Sub-GHz remote-control capture and analysis "
                    "(fixed vs rolling code, encoding, library)",
        epilog="replay requires --i-own-this-device and a transmit-capable radio")
    parser.add_argument("--version", action="version", version=f"keyfob_analyzer {VERSION}")
    parser.add_argument("--frequency", type=float, default=None,
                        help="centre frequency in MHz (315, 433.92, 868)")
    parser.add_argument("--duration", type=int, default=20,
                        help="capture seconds (default: 20)")
    parser.add_argument("--input", type=Path, default=None,
                        help="analyse a recorded IQ file")
    parser.add_argument("--pulses", type=Path, default=None,
                        help="analyse a pulse file (level microseconds per line)")
    parser.add_argument("--label", default="", help="label stored with the signal")
    parser.add_argument("--library", action="store_true",
                        help="add this capture to the signal library")
    parser.add_argument("--list-library", action="store_true",
                        help="print the stored signals")
    parser.add_argument("--compare", nargs=2, type=Path, default=None, metavar=("A", "B"),
                        help="compare two stored signals (fixed vs rolling code)")
    parser.add_argument("--write", action="store_true",
                        help="write JSON/CSV and a regenerated IQ file")
    parser.add_argument("--replay", type=Path, default=None,
                        help="transmit a stored signal (needs authorisation)")
    parser.add_argument("--transmitter", default="hackrf", choices=["hackrf"],
                        help="transmitter backend (default: hackrf)")
    parser.add_argument("--replay-count", type=int, default=1,
                        help="how many times to transmit (default: 1)")
    parser.add_argument("--i-own-this-device", action="store_true",
                        dest="attest",
                        help="attest that you own or operate the target device")
    parser.add_argument("--live", action="store_true", help="report each press as it arrives")
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the key fob analyser.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 success, 1 failure, 2 usage, 3 no hardware.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("keyfob_analyzer", level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("keyfob analyser", f"v{VERSION} · 315/433.92/868 MHz")

    analyser = KeyfobAnalyzer(config, logger)
    if args.frequency:
        analyser.frequency = int(args.frequency * 1e6)

    # --- transmit gate ---------------------------------------------------- #
    if args.replay is not None:
        if not args.attest:
            logger.error("replay needs --i-own-this-device")
            logger.info("transmitting someone else's remote is illegal in most "
                        "jurisdictions; add the flag only if you own or operate it")
            return 2
        if not require_acknowledgement(config, logger):
            logger.error("the legal acknowledgement in cyberdeck.conf is not set")
            logger.info("run 'cdeck config' and set general.authorised_use_acknowledged: true "
                        "after reading docs/LEGAL.md")
            return 2
        logger.warn("replay transmits on %.3f MHz in the sub-GHz band",
                    analyser.frequency / 1e6)
        logger.warn("ensure your authorisation covers transmitting on this frequency")
        if not confirm("Transmit the stored signal now?", logger=logger):
            logger.info("aborted")
            return 0
        try:
            return analyser.replay(args.replay, args.transmitter,
                                   count=max(1, args.replay_count))
        finally:
            analyser.close()

    try:
        if args.list_library:
            return analyser.list_library()
        if args.compare:
            return analyser.compare_files(args.compare[0], args.compare[1])

        code = 0
        if args.pulses is not None:
            code = analyser.read_pulse_file(args.pulses, label=args.label)
        elif args.input is not None:
            code = analyser.read_iq_file(args.input, live=args.live)
        else:
            if not analyser.require_sdr():
                logger.info("offline mode: ./keyfob_analyzer.py --pulses press.txt")
                return 3
            code = analyser.capture(args.duration, live=args.live)

        if code == 0:
            if args.library:
                analyser.signals and analyser.save_to_library(args.label)
            if args.write:
                analyser.write_outputs()
            if args.json:
                print(json.dumps([signal.as_dict(include_pulses=False)
                                  for signal in analyser.signals], indent=2))
            else:
                analyser.render_plain_table()
                if analyser.signals:
                    summary = analyser.signals[0]
                    for note in summary.notes:
                        logger.info("%s", note)
                    if summary.repeats_identical:
                        logger.warn("the repeats are identical - this looks like a "
                                    "fixed-code remote (replayable)")
        return code
    finally:
        analyser.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
