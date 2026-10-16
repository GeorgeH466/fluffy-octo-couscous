#!/usr/bin/env python3
"""
rf_spectrum.py - RTL-SDR spectrum / waterfall display for cyberdeck-arsenal
==========================================================================

Description
-----------
Drives ``rtl_power`` to sweep a frequency range and renders the result as a
terminal heatmap (waterfall) plus a live bar chart of the current sweep, with
peak detection and logging of interesting carriers.

The module degrades gracefully: on a machine with no SDR hardware it explains
what is missing, prints the recommended hardware and exits 0, so it can be
called safely from the HUD or from scripts.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; rtl-sdr package (rtl_power); rich (optional);
              SDR receiver (RTL-SDR, HackRF via SoapySDR wrapper, Airspy)
Licence     : MIT - passive reception only, respect local radio regulations

Usage
-----
    cdeck rf
    python3 dashboard/rf_spectrum.py --start 88 --end 108          # FM broadcast
    python3 dashboard/rf_spectrum.py --start 433 --end 435 --detect-threshold 12
    python3 dashboard/rf_spectrum.py --list-ranges
    python3 dashboard/rf_spectrum.py --once --json > sweep.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple
import collections

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
        C, Config, Database, Hardware, Logger, colour, deps, now_iso, run, write_json,
    )
except ImportError as exc:
    print(f"rf_spectrum: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Curated frequency ranges - handy defaults for common deck use cases
KNOWN_RANGES: Dict[str, Dict[str, Any]] = {
    "fm": {"start": 87.5, "end": 108.0, "bins": 20000, "description": "FM broadcast radio"},
    "airband": {"start": 118.0, "end": 137.0, "bins": 12500, "description": "Aviation VHF (AM voice)"},
    "noaa": {"start": 162.0, "end": 163.0, "bins": 5000, "description": "NOAA weather radio"},
    "pmr446": {"start": 446.0, "end": 446.2, "bins": 3000, "description": "PMR446 licence-free handhelds"},
    "ism433": {"start": 433.0, "end": 434.8, "bins": 5000, "description": "433 MHz ISM (keyfobs, TPMS, sensors)"},
    "ism868": {"start": 868.0, "end": 870.0, "bins": 5000, "description": "868 MHz ISM (EU sensors, alarms)"},
    "ism915": {"start": 902.0, "end": 928.0, "bins": 20000, "description": "915 MHz ISM (US sensors)"},
    "adsb": {"start": 1089.0, "end": 1091.0, "bins": 4000, "description": "ADS-B aircraft transponders"},
    "gsm900": {"start": 935.0, "end": 960.0, "bins": 12500, "description": "GSM-900 downlink (receive only)"},
    "lte800": {"start": 791.0, "end": 821.0, "bins": 12500, "description": "LTE-800 downlink (receive only)"},
    "gps": {"start": 1575.0, "end": 1576.0, "bins": 2000, "description": "GPS L1 (usually below the noise floor)"},
}

#: Waterfall ramp from quiet to loud
RAMP = " .:-=+*#%@"


@dataclass
class Sweep:
    """A single rtl_power sweep row."""

    timestamp: float
    start_hz: float
    step_hz: float
    powers_db: List[float] = field(default_factory=list)

    def frequencies_mhz(self) -> List[float]:
        """Return the centre frequency of each bin in MHz."""
        return [(self.start_hz + index * self.step_hz) / 1e6
                for index in range(len(self.powers_db))]

    def peak(self) -> Tuple[float, float]:
        """Return ``(frequency_mhz, power_db)`` of the strongest bin."""
        if not self.powers_db:
            return (0.0, -999.0)
        index = max(range(len(self.powers_db)), key=lambda i: self.powers_db[i])
        return ((self.start_hz + index * self.step_hz) / 1e6, self.powers_db[index])

    def median(self) -> float:
        """Return the median power level (noise floor estimate)."""
        if not self.powers_db:
            return -999.0
        ordered = sorted(self.powers_db)
        return ordered[len(ordered) // 2]


class RtlPowerCapture:
    """Streams sweeps from rtl_power."""

    def __init__(self, start_mhz: float, end_mhz: float, bin_size: int, interval: float,
                 gain: str, device_index: int, logger: Logger,
                 crop: bool = True, squelch: Optional[float] = None) -> None:
        """Configure a sweep between *start_mhz* and *end_mhz*."""
        self.start_mhz = start_mhz
        self.end_mhz = end_mhz
        self.bin_size = bin_size
        self.interval = interval
        self.gain = gain
        self.device_index = device_index
        self.logger = logger
        self.crop = crop
        self.squelch = squelch
        self.process: Optional[subprocess.Popen[str]] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.sweeps: Deque[Sweep] = collections.deque(maxlen=200)
        self.lock = threading.Lock()
        self.detections: List[Dict[str, Any]] = []
        self.last_error: str = ""

    def command(self) -> List[str]:
        """Build the rtl_power command line."""
        binary = deps.which("rtl_power") or "rtl_power"
        cmd = [
            binary,
            "-f", f"{self.start_mhz}M:{self.end_mhz}M:{self.bin_size}",
            "-i", str(self.interval),
            "-d", str(self.device_index),
        ]
        if self.gain and str(self.gain).lower() != "auto":
            cmd += ["-g", str(self.gain)]
        if self.crop:
            cmd += ["-c", "20%"]
        if self.squelch is not None:
            cmd += ["-S", str(self.squelch)]
        cmd += ["/dev/stdout"]
        return cmd

    def start(self) -> bool:
        """Launch rtl_power and start parsing its CSV output."""
        try:
            self.process = subprocess.Popen(  # noqa: S603 - fixed argv
                self.command(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
        except OSError as exc:
            self.last_error = f"could not start rtl_power: {exc}"
            self.logger.error(self.last_error)
            return False
        self.running = True
        self.thread = threading.Thread(target=self._reader, name="rtl-power", daemon=True)
        self.thread.start()
        self.logger.info(f"sweeping {self.start_mhz}-{self.end_mhz} MHz "
                         f"(bin {self.bin_size} Hz, interval {self.interval}s)")
        return True

    def _reader(self) -> None:
        """Parse rtl_power CSV rows until the process exits."""
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            if not self.running:
                break
            sweep = self._parse_line(line)
            if sweep:
                with self.lock:
                    self.sweeps.append(sweep)
                    self._detect(sweep)

    def _parse_line(self, line: str) -> Optional[Sweep]:
        """Convert one CSV line into a :class:`Sweep`."""
        try:
            row = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            return None
        if len(row) < 7:
            return None
        try:
            # rtl_power CSV: date, time, hz_low, hz_high, hz_step, samples, db...
            stamps = f"{row[0].strip()} {row[1].strip()}"
            try:
                from datetime import datetime
                timestamp = datetime.strptime(stamps, "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                timestamp = time.time()
            start_hz = float(row[2])
            step_hz = float(row[4])
            powers = [float(value) for value in row[6:]]
        except (ValueError, IndexError):
            return None
        return Sweep(timestamp=timestamp, start_hz=start_hz, step_hz=step_hz, powers_db=powers)

    def _detect(self, sweep: Sweep) -> None:
        """Record bins that stand out from the noise floor."""
        if not sweep.powers_db:
            return
        noise = sweep.median()
        threshold = 12.0
        for frequency, power in zip(sweep.frequencies_mhz(), sweep.powers_db):
            if power - noise >= threshold:
                key = round(frequency, 3)
                # Collapse adjacent bins: only log when the peak moves or grows
                if self.detections and abs(self.detections[-1]["frequency_mhz"] - key) < 0.05:
                    if power > self.detections[-1]["power_db"]:
                        self.detections[-1]["power_db"] = round(power, 1)
                    continue
                self.detections.append({
                    "frequency_mhz": key,
                    "power_db": round(power, 1),
                    "noise_floor_db": round(noise, 1),
                    "snr_db": round(power - noise, 1),
                    "ts": now_iso(),
                })
                self.detections = self.detections[-200:]

    def snapshot(self) -> Optional[Sweep]:
        """Return the most recent sweep."""
        with self.lock:
            return self.sweeps[-1] if self.sweeps else None

    def history(self, count: int = 40) -> List[Sweep]:
        """Return the most recent *count* sweeps, oldest first."""
        with self.lock:
            return list(self.sweeps)[-count:]

    def stop(self) -> None:
        """Terminate rtl_power."""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.process.kill()
                except OSError:
                    pass


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_waterfall(sweeps: Sequence[Sweep], width: int = 100, height: int = 22) -> List[str]:
    """Render sweeps as a waterfall heatmap."""
    if not sweeps:
        return ["  (no sweep data yet)"]
    # Downsample each sweep to the requested width and stack the most recent rows
    rows: List[List[float]] = []
    for sweep in sweeps[-height:]:
        values = sweep.powers_db
        if not values:
            continue
        if len(values) > width:
            step = len(values) / width
            sampled = [max(values[int(i * step):max(int(i * step) + 1, int((i + 1) * step))])
                       for i in range(width)]
        else:
            sampled = list(values) + [values[-1]] * (width - len(values))
        rows.append(sampled)
    if not rows:
        return ["  (no bins in the requested range)"]

    floor = min(min(row) for row in rows)
    ceiling = max(max(row) for row in rows)
    span = max(ceiling - floor, 1.0)

    lines: List[str] = []
    start_mhz = sweeps[0].start_hz / 1e6
    end_mhz = (sweeps[0].start_hz + len(sweeps[0].powers_db) * sweeps[0].step_hz) / 1e6
    lines.append(f"  {start_mhz:7.3f} MHz ╞{'═' * width}╡ {end_mhz:7.3f} MHz")
    for row in rows:
        line = "".join(RAMP[min(len(RAMP) - 1,
                                max(0, int((value - floor) / span * (len(RAMP) - 1))))]
                       for value in row)
        lines.append(f"  {' ' * 12}│{line}│")
    lines.append(f"  {floor:7.1f} dB floor{' ' * (max(width - 20, 0))}ceil {ceiling:7.1f} dB")
    return lines


def render_bar_chart(sweep: Optional[Sweep], width: int = 100, height: int = 12) -> List[str]:
    """Render the current sweep as a coarse bar chart."""
    if not sweep or not sweep.powers_db:
        return ["  (no data)"]
    values = sweep.powers_db
    # Group bins into `width` columns taking the maximum of each group
    if len(values) > width:
        step = len(values) / width
        columns = [max(values[int(i * step):max(int(i * step) + 1, int((i + 1) * step))])
                   for i in range(width)]
    else:
        columns = list(values)
    floor = min(columns)
    ceiling = max(columns)
    span = max(ceiling - floor, 1.0)
    lines: List[str] = []
    for level in range(height, 0, -1):
        threshold = floor + span * (level / height)
        line = "".join("█" if value >= threshold else " " for value in columns)
        label = f"{threshold:6.1f}" if level % 3 == 0 or level == height else "      "
        lines.append(f"  {label} ┤{line}")
    lines.append(f"         └{'─' * len(columns)}")
    frequencies = sweep.frequencies_mhz()
    if frequencies:
        lines.append(f"          {frequencies[0]:.3f}{' ' * max(len(columns) - 24, 1)}"
                     f"{frequencies[-1]:.3f} MHz")
    peak_frequency, peak_power = sweep.peak()
    lines.append(f"  peak {peak_power:.1f} dB at {peak_frequency:.3f} MHz   "
                 f"floor {sweep.median():.1f} dB")
    return lines


def render_plain(capture: Optional[RtlPowerCapture], detections: Sequence[Dict[str, Any]]) -> str:
    """Plain-text report used by --once and non-rich terminals."""
    lines = [colour(f"  RF SPECTRUM  ::  {now_iso()}", C.BRIGHT_CYAN)]
    if capture:
        sweep = capture.snapshot()
        lines.append("")
        lines.append(colour("  CURRENT SWEEP", C.BOLD))
        lines.extend(render_bar_chart(sweep))
        lines.append("")
        lines.append(colour("  WATERFALL (most recent below)", C.BOLD))
        lines.extend(render_waterfall(capture.history(22)))
    if detections:
        lines.append("")
        lines.append(colour("  DETECTIONS", C.BOLD))
        for detection in list(detections)[-15:]:
            lines.append(f"  {detection['ts'][11:19]}  {detection['frequency_mhz']:>10.3f} MHz  "
                         f"{detection['power_db']:>6.1f} dB  SNR {detection['snr_db']:>5.1f} dB")
    return "\n".join(lines)


def run_live(capture: RtlPowerCapture, logger: Logger, refresh: float,
             duration: Optional[float], record: bool) -> int:
    """Run the rich live spectrum view."""
    try:
        from rich.console import Console, Group
        from rich.live import Live
        from rich.panel import Panel
        from rich.text import Text
    except ImportError:
        logger.warn("rich not installed - printing a snapshot instead")
        time.sleep(max(3.0, refresh * 3))
        print(render_plain(capture, capture.detections))
        return 0

    console = Console()
    deadline = time.time() + duration if duration else None

    def build() -> Panel:
        sweep = capture.snapshot()
        header = Text()
        header.append("  RF SPECTRUM  ", style="bold #00ffd5")
        header.append(f"{capture.start_mhz:.3f}-{capture.end_mhz:.3f} MHz  ", style="dim")
        header.append(f"device {capture.device_index}  ", style="dim")
        header.append(f"sweeps {len(capture.sweeps)}  ", style="dim")
        if sweep:
            peak_frequency, peak_power = sweep.peak()
            header.append(f"peak {peak_power:.1f} dB @ {peak_frequency:.3f} MHz  ", style="bold #ff79c6")
            header.append(f"floor {sweep.median():.1f} dB", style="dim")
        bars = Text("\n".join(render_bar_chart(sweep, 96, 10)), style="#8bd5ff")
        waterfall = Text("\n".join(render_waterfall(capture.history(20), 96, 18)), style="#00ffd5")
        detections = Text()
        for detection in list(capture.detections)[-6:]:
            detections.append(f"  {detection['ts'][11:19]}  ", style="dim")
            detections.append(f"{detection['frequency_mhz']:>9.3f} MHz  ", style="bold #ff79c6")
            detections.append(f"{detection['power_db']:>6.1f} dB  ", style="#ffb86c")
            detections.append(f"SNR {detection['snr_db']:>5.1f} dB\n", style="dim")
        if not capture.detections:
            detections.append("  no signals above threshold yet", style="dim")
        return Panel(Group(header, Text(""), bars, Text(""), waterfall, Text(""), detections),
                     border_style="#5a6b7a",
                     subtitle="q to quit · passive reception only")

    try:
        with Live(build(), console=console, refresh_per_second=max(1, int(1 / refresh)),
                  screen=True) as live:
            while True:
                live.update(build())
                if deadline and time.time() > deadline:
                    break
                time.sleep(refresh)
    except KeyboardInterrupt:
        pass

    if record and capture.detections:
        try:
            output = Path(str(Config().load().get("sdr.capture_dir", "data/rf")))
            output.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            destination = output / f"spectrum_{stamp}.json"
            write_json(destination, {
                "range_mhz": [capture.start_mhz, capture.end_mhz],
                "detections": capture.detections,
            })
            logger.ok(f"detections written to {destination}")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"could not write detections: {exc}")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="rf_spectrum.py",
        description="RTL-SDR spectrum and waterfall display (passive reception)",
        epilog="Also available as: cdeck rf")
    parser.add_argument("--start", type=float, default=None, help="start frequency in MHz")
    parser.add_argument("--end", type=float, default=None, help="end frequency in MHz")
    parser.add_argument("--range", dest="preset", default=None, choices=sorted(KNOWN_RANGES),
                        help="use a curated frequency range")
    parser.add_argument("--list-ranges", action="store_true", help="list the curated ranges and exit")
    parser.add_argument("--bin-size", type=int, default=None, help="rtl_power bin size in Hz")
    parser.add_argument("--interval", type=float, default=None, help="seconds per sweep")
    parser.add_argument("--gain", default=None, help="gain in dB or 'auto'")
    parser.add_argument("--device", type=int, default=None, help="RTL-SDR device index")
    parser.add_argument("--refresh", type=float, default=1.0, help="display refresh interval")
    parser.add_argument("--detect-threshold", type=float, default=12.0,
                        help="SNR in dB above the noise floor to record a detection")
    parser.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    parser.add_argument("--record", action="store_true", help="write detections to data/rf/")
    parser.add_argument("--once", action="store_true", help="print a snapshot and exit")
    parser.add_argument("--json", action="store_true", help="emit detections as JSON")
    parser.add_argument("--allow-missing-hardware", action="store_true",
                        help="exit 0 (not 3) when no SDR is present")
    parser.add_argument("--version", action="version", version=f"rf_spectrum {__version__}")
    return parser.parse_args(argv)


def hardware_report() -> Tuple[bool, List[str]]:
    """Return (hardware_available, report lines)."""
    lines: List[str] = []
    available = False
    devices = Hardware.sdr_devices()
    if deps.have("rtl_power"):
        lines.append(colour("✔ rtl_power found", C.BRIGHT_GREEN))
    else:
        lines.append(colour("✘ rtl_power missing - install with: sudo pacman -S rtl-sdr", C.BRIGHT_RED))
    if devices:
        available = True
        for device in devices:
            lines.append(colour(f"✔ SDR detected: {device['description']}", C.BRIGHT_GREEN))
    else:
        lines.append(colour("✘ no SDR receiver detected on the USB bus", C.BRIGHT_RED))
        lines.append("  recommended hardware:")
        lines.append("    • RTL-SDR Blog V4 / V3        (~£30, 24 MHz - 1.7 GHz, HF with direct sampling)")
        lines.append("    • Nooelec NESDR SMArt v5      (~£35, well shielded, good for 433 MHz)")
        lines.append("    • HackRF One                  (~£300, 1 MHz - 6 GHz, also transmits)")
        lines.append("    • Airspy Mini / R2            (~£100+, best dynamic range for weak signals)")
        lines.append("  note: DVB-T dongles need the DVB driver blacklisted:")
        lines.append("    echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/rtl-sdr-blacklist.conf")
    if not shutil.which("lsusb"):
        lines.append(colour("! usbutils missing - USB detection is limited", C.YELLOW))
    return available, lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("rf_spectrum", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)))

    if args.list_ranges:
        print(colour("  curated frequency ranges", C.BOLD))
        for name, info in sorted(KNOWN_RANGES.items()):
            print(f"  {name:<10} {info['start']:7.3f} - {info['end']:7.3f} MHz   {info['description']}")
        return 0

    available, report = hardware_report()
    if not available:
        logger.banner("rf spectrum", "no SDR hardware detected")
        for line in report:
            print(f"  {line}")
        print()
        logger.info("passive SDR features stay disabled until a receiver is attached")
        logger.info("re-check with: cdeck hardware")
        return 0 if args.allow_missing_hardware else 3

    # Resolve the sweep range
    start_mhz = args.start
    end_mhz = args.end
    preset = args.preset
    if preset:
        start_mhz = start_mhz or float(KNOWN_RANGES[preset]["start"])
        end_mhz = end_mhz or float(KNOWN_RANGES[preset]["end"])
    start_mhz = start_mhz or float(config.get("sdr.sweep_start_mhz", 88))
    end_mhz = end_mhz or float(config.get("sdr.sweep_end_mhz", 108))
    if end_mhz <= start_mhz:
        logger.error("the end frequency must be greater than the start frequency")
        return 2
    if start_mhz < 24 or end_mhz > 1766:
        logger.warn("outside the usual RTL-SDR range (24-1766 MHz) - results may be empty")

    bin_size = args.bin_size or int(config.get("sdr.rtl_power_bin_size", 20000))
    interval = args.interval or float(config.get("sdr.rtl_power_interval", 2))
    gain = args.gain if args.gain is not None else str(config.get("sdr.gain", "auto"))
    device = args.device if args.device is not None else int(config.get("sdr.device_index", 0))

    capture = RtlPowerCapture(start_mhz, end_mhz, bin_size, interval, gain, device, logger)
    if not capture.start():
        logger.error(capture.last_error or "rtl_power failed to start")
        logger.info("check the device with: rtl_test -t")
        return 3

    try:
        if args.once or args.json:
            time.sleep(max(3.0, interval * 2))
            if args.json:
                sweep = capture.snapshot()
                print(json.dumps({
                    "range_mhz": [start_mhz, end_mhz],
                    "bins": len(sweep.powers_db) if sweep else 0,
                    "floor_db": round(sweep.median(), 2) if sweep else None,
                    "peak": ({"frequency_mhz": sweep.peak()[0], "power_db": sweep.peak()[1]}
                             if sweep else None),
                    "detections": capture.detections,
                }, indent=2))
            else:
                print(render_plain(capture, capture.detections))
            return 0
        return run_live(capture, logger, args.refresh, args.duration, args.record)
    finally:
        capture.stop()
        logger.info(f"sweep stopped ({len(capture.detections)} detection(s) recorded)")


if __name__ == "__main__":
    sys.exit(main())
