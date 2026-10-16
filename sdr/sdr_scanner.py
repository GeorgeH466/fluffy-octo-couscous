#!/usr/bin/env python3
"""
sdr/sdr_scanner.py - RF spectrum survey and band occupancy mapping.
==================================================================

Description
-----------
Sweeps a frequency range with an RTL-SDR (``rtl_power``), stores the power
readings, detects peaks above the local noise floor, and reports what it found:

* band presets for the bands an operator usually cares about (FM broadcast,
  airband, ADSB, pager, ISM 433/868/915, GSM/LTE downlinks, WiFi 2.4, GPS L1)
* peak detection with a configurable threshold over the smoothed noise floor
* persistence of every sweep as CSV plus a JSON summary and a PNG/ASCII
  waterfall overview, so a survey can be compared with the next one
* optional known-signal labelling (pager, TPMS, ADSB, WiFi, cell) so a peak is
  not just a number
* live Rich display when the toolkit venv provides it, plain text otherwise

The scanner is receive-only: nothing in this module transmits.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: rtl-sdr (rtl_power, rtl_test); optional: rich (live table),
              matplotlib (PNG waterfall - a CSV is always written)
Licence     : MIT - receive-only. Listening to some transmissions (e.g. cellular
              traffic, cordless phones) is regulated; check local law.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
        now_iso,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: Band presets: start_hz, stop_hz, bin_hz (rtl_power bin width from -f ...:width)
BANDS: Dict[str, Dict[str, Any]] = {
    "fm": {"start": 87_500_000, "stop": 108_000_000, "bin": 100_000,
           "note": "FM broadcast - RDS, traffic, popular for RF fingerprinting"},
    "airband": {"start": 118_000_000, "stop": 137_000_000, "bin": 25_000,
                "note": "VHF airband AM voice - listen-only; transmission is illegal"},
    "noaa": {"start": 162_400_000, "stop": 162_550_000, "bin": 12_500,
             "note": "NOAA/marine weather broadcasts"},
    "adsb": {"start": 1_085_000_000, "stop": 1_095_000_000, "bin": 200_000,
             "note": "ADS-B 1090ES - aircraft position broadcasts"},
    "pager": {"start": 153_000_000, "stop": 155_000_000, "bin": 12_500,
              "note": "Common POCSAG/FLEX pager band (many are still live)"},
    "ism433": {"start": 433_000_000, "stop": 434_800_000, "bin": 12_500,
               "note": "EU ISM - TPMS, keyfobs, weather stations, remotes"},
    "ism868": {"start": 863_000_000, "stop": 870_000_000, "bin": 12_500,
               "note": "EU ISM - LoRa, smart meters, alarm sensors"},
    "ism915": {"start": 902_000_000, "stop": 928_000_000, "bin": 25_000,
               "note": "US ISM - TPMS, remotes, Z-Wave"},
    "gsm900": {"start": 925_000_000, "stop": 960_000_000, "bin": 200_000,
               "note": "GSM/LTE downlink - do not decode subscriber traffic"},
    "lte1800": {"start": 1_805_000_000, "stop": 1_880_000_000, "bin": 200_000,
                "note": "LTE band 3 downlink"},
    "wifi24": {"start": 2_400_000_000, "stop": 2_500_000_000, "bin": 500_000,
               "note": "2.4 GHz WiFi/BLE - good for occupancy, not for decoding"},
    "gps": {"start": 1_574_000_000, "stop": 1_576_000_000, "bin": 100_000,
            "note": "GPS L1 - below the noise floor by design; jamming detection only"},
}

#: Frequency ranges that commonly carry the signals this deck cares about
KNOWN_SIGNALS: Tuple[Tuple[str, float, float, str], ...] = (
    ("ADSB 1090ES", 1_087_000_000, 1_093_000_000, "aircraft position"),
    ("POCSAG/FLEX pager", 153_000_000, 155_000_000, "text pagers"),
    ("433.92 MHz ISM centre", 433_050_000, 434_790_000, "remotes/TPMS/keyfobs"),
    ("868 MHz ISM centre", 863_000_000, 870_000_000, "LoRa/meters/sensors"),
    ("915 MHz ISM centre", 902_000_000, 928_000_000, "US remotes/TPMS"),
    ("WiFi/BLE 2.4 GHz", 2_400_000_000, 2_483_500_000, "802.11b/g/n and BLE"),
    ("WiFi 5 GHz (U-NII-1)", 5_150_000_000, 5_250_000_000, "802.11a/n/ac"),
    ("GPS L1", 1_574_420_000, 1_576_420_000, "GNSS (should be below noise)"),
    ("FM broadcast", 87_500_000, 108_000_000, "audio broadcast"),
    ("Airband voice", 118_000_000, 137_000_000, "AM voice"),
    ("Marine VHF", 156_000_000, 163_000_000, "channel 16/70 etc."),
    ("GSM 900 downlink", 935_000_000, 960_000_000, "cellular - do not decode"),
)


@dataclass
class Peak:
    """A detected signal peak in the spectrum."""

    frequency_hz: int
    power_db: float
    bandwidth_hz: int
    label: str = ""
    note: str = ""
    detected: str = field(default_factory=now_iso)

    @property
    def frequency_mhz(self) -> float:
        """Frequency in MHz (for reports)."""
        return round(self.frequency_hz / 1e6, 3)

    def as_dict(self) -> Dict[str, Any]:
        """Return the peak as a plain dictionary."""
        return {
            "frequency_hz": self.frequency_hz,
            "frequency_mhz": self.frequency_mhz,
            "power_db": round(self.power_db, 2),
            "bandwidth_hz": self.bandwidth_hz,
            "label": self.label,
            "note": self.note,
            "detected": self.detected,
        }


@dataclass
class Sweep:
    """One complete sweep of a band."""

    band: str
    start_hz: int
    stop_hz: int
    started: str
    finished: str
    bins: List[Tuple[int, float]] = field(default_factory=list)
    peaks: List[Peak] = field(default_factory=list)
    noise_floor_db: float = 0.0
    gain: str = "auto"
    device: str = ""

    @property
    def coverage_mhz(self) -> float:
        """Bandwidth covered by the sweep, in MHz."""
        return round((self.stop_hz - self.start_hz) / 1e6, 3)

    def as_dict(self, include_bins: bool = False) -> Dict[str, Any]:
        """Return the sweep as a plain dictionary."""
        payload: Dict[str, Any] = {
            "band": self.band,
            "start_hz": self.start_hz,
            "stop_hz": self.stop_hz,
            "coverage_mhz": self.coverage_mhz,
            "started": self.started,
            "finished": self.finished,
            "noise_floor_db": round(self.noise_floor_db, 2),
            "gain": self.gain,
            "device": self.device,
            "bin_count": len(self.bins),
            "peaks": [peak.as_dict() for peak in self.peaks],
        }
        if include_bins:
            payload["bins"] = [{"hz": hz, "db": round(db, 2)} for hz, db in self.bins]
        return payload


class SpectrumScanner:
    """Runs rtl_power sweeps, detects peaks and stores the results.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
    """

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                              "/opt/cyberdeck-arsenal")))
        self.output_dir = self.install_dir / "data" / "rf"
        self.gain = str(config.get("sdr.gain", "auto"))
        self.ppm = int(config.get("sdr.ppm", 0) or 0)
        self.device_index = int(config.get("sdr.device_index", 0) or 0)
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)

    # -- capability -------------------------------------------------------- #
    @staticmethod
    def sdr_devices() -> List[Dict[str, str]]:
        """Return the SDR devices the library can see."""
        return Hardware.sdr_devices()

    @staticmethod
    def have_tool(binary: str) -> bool:
        """Return True when *binary* is on PATH."""
        return shutil.which(binary) is not None

    def require_sdr(self) -> bool:
        """Check for a usable SDR and the rtl_power tool.

        Returns:
            True when a sweep can be attempted.
        """
        if not self.have_tool("rtl_power"):
            self.logger.error("rtl_power is not installed")
            self.logger.info("install the RTL-SDR tools with: sudo pacman -S rtl-sdr")
            return False
        devices = self.sdr_devices()
        if not devices:
            self.logger.error("no SDR device detected")
            self.logger.info("plug in an RTL-SDR (or check dmesg for a driver error)")
            return False
        self.logger.info("SDR device: %s", devices[0].get("name", "unknown"))
        return True

    # -- sweeping ---------------------------------------------------------- #
    def build_command(self, band: Dict[str, Any], output: Path,
                      integration: int, duration: int) -> List[str]:
        """Build the rtl_power command line for a sweep.

        Args:
            band: the preset dictionary (start/stop/bin).
            output: CSV file rtl_power should write.
            integration: seconds averaged per sweep row.
            duration: total seconds to run.

        Returns:
            The command as an argument list.
        """
        frequencies = f"{band['start']}:{band['stop']}:{band['bin']}"
        command = [
            "rtl_power",
            "-f", frequencies,
            "-i", str(integration),
            "-e", str(duration),
            "-g", self.gain,
            "-d", str(self.device_index),
            "-c", "25%",       # crop the edges where the tuner rolls off
            "-p", str(self.ppm),
            output.as_posix(),
        ]
        return command

    def sweep(self, band_name: str, duration: int = 30, integration: int = 2,
              start_hz: Optional[int] = None, stop_hz: Optional[int] = None,
              bin_hz: Optional[int] = None, threshold_db: float = 8.0,
              gain: Optional[str] = None) -> Sweep:
        """Run one sweep of a band.

        Args:
            band_name: preset name, or ``custom`` with explicit frequencies.
            duration: seconds to record.
            integration: seconds per integration row.
            start_hz / stop_hz / bin_hz: overrides for custom ranges.
            threshold_db: dB above the noise floor that counts as a peak.
            gain: override the configured gain.

        Returns:
            The completed :class:`Sweep`.
        """
        preset = dict(BANDS.get(band_name, BANDS["ism433"]))
        if start_hz:
            preset["start"] = start_hz
        if stop_hz:
            preset["stop"] = stop_hz
        if bin_hz:
            preset["bin"] = bin_hz
        if presets_needed(preset["start"], preset["stop"], preset["bin"]):
            # rtl_power has a hard limit of ~2.4 MHz per tuning step before it
            # has to hop: warn rather than silently producing gaps
            self.logger.warn("range is wider than one tuner step - rtl_power will hop, "
                             "which can miss short transmissions")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw = self.output_dir / f"sweep_{band_name}_{stamp}.csv"
        if gain:
            self.gain = gain

        sweep = Sweep(
            band=band_name,
            start_hz=int(preset["start"]),
            stop_hz=int(preset["stop"]),
            started=now_iso(),
            finished="",
            gain=self.gain,
            device=self.sdr_devices()[0].get("name", "rtl-sdr") if self.sdr_devices() else "",
        )

        command = self.build_command(preset, raw, integration, duration)
        self.logger.info("sweeping %s: %.3f-%.3f MHz, bin %s kHz, %ss, gain %s",
                         band_name, sweep.start_hz / 1e6, sweep.stop_hz / 1e6,
                         preset["bin"] // 1000, duration, self.gain)
        self.logger.debug("command: %s", " ".join(command))

        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            self.logger.error("could not start rtl_power: %s", exc)
            return sweep

        # Show progress while rtl_power works, and allow Ctrl-C to stop early
        stopped = False

        def stop(_signum: int, _frame: Any) -> None:
            nonlocal stopped
            stopped = True

        for name in ("SIGINT", "SIGTERM"):
            try:
                signal.signal(getattr(signal, name), stop)
            except (ValueError, OSError):  # pragma: no cover
                pass

        started = time.time()
        while process.poll() is None and not stopped:
            time.sleep(0.5)
            if self.logger.level_name == "DEBUG":
                continue
            elapsed = int(time.time() - started)
            print(f"\r  sweeping… {elapsed}/{duration}s", end="", flush=True)
        print("\r" + " " * 40 + "\r", end="")

        if stopped:
            process.terminate()
            self.logger.warn("sweep interrupted after %ss", int(time.time() - started))
        try:
            _out, err = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()
            err = ""
        if err and "error" in err.lower():
            for line in err.strip().splitlines()[:5]:
                self.logger.warn("rtl_power: %s", line.strip())

        sweep.finished = now_iso()
        if raw.is_file() and raw.stat().st_size > 0:
            sweep.bins = self.parse_rtl_power_csv(raw)
            self.logger.ok("recorded %s bin(s) to %s", len(sweep.bins), raw.name)
        else:
            self.logger.error("rtl_power produced no data")
            self.logger.info("check the dongle: rtl_test -t   (or kill any process using it)")

        if sweep.bins:
            sweep.noise_floor_db = self.noise_floor(sweep.bins)
            sweep.peaks = self.detect_peaks(sweep.bins, sweep.noise_floor_db, threshold_db)
            self.logger.info("noise floor %.1f dB · %d peak(s) above %.1f dB",
                             sweep.noise_floor_db, len(sweep.peaks), threshold_db)
            self.write_outputs(sweep, raw)
        return sweep

    @staticmethod
    def parse_rtl_power_csv(path: Path) -> List[Tuple[int, float]]:
        """Parse an rtl_power CSV into ``(frequency_hz, power_db)`` pairs.

        rtl_power rows look like::

            2026-10-16, 14:00:00, 433000000, 434800000, 12500.00, 20, -45.2, -50.1, ...

        Args:
            path: the CSV file written by rtl_power.

        Returns:
            A list of (frequency, power) tuples averaged across sweeps.
        """
        accumulated: Dict[int, List[float]] = {}
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return []
        for line in text.splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 7:
                continue
            try:
                low = int(float(parts[2]))
                step = float(parts[4])
            except (ValueError, IndexError):
                continue
            if step <= 0:
                continue
            for index, value in enumerate(parts[6:]):
                try:
                    power = float(value)
                except ValueError:
                    continue
                frequency = int(low + step * index)
                accumulated.setdefault(frequency, []).append(power)
        return sorted((hz, sum(values) / len(values))
                      for hz, values in accumulated.items())

    @staticmethod
    def noise_floor(bins: Sequence[Tuple[int, float]]) -> float:
        """Estimate the noise floor as the median of the lowest third.

        Args:
            bins: the (frequency, power) pairs.

        Returns:
            The estimated noise floor in dB.
        """
        if not bins:
            return 0.0
        powers = sorted(power for _hz, power in bins)
        window = powers[: max(1, len(powers) // 3)]
        return sum(window) / len(window)

    @staticmethod
    def detect_peaks(bins: Sequence[Tuple[int, float]], floor_db: float,
                     threshold_db: float, max_peaks: int = 40) -> List[Peak]:
        """Find peaks that stand out from the noise floor.

        Args:
            bins: sorted (frequency, power) pairs.
            floor_db: the estimated noise floor.
            threshold_db: how far above the floor a peak must be.
            max_peaks: cap on the number of peaks returned.

        Returns:
            Peaks sorted by descending power.
        """
        if not bins:
            return []
        threshold = floor_db + threshold_db
        peaks: List[Peak] = []
        index = 0
        while index < len(bins):
            frequency, power = bins[index]
            if power < threshold:
                index += 1
                continue
            # Walk the ridge (values within 3 dB of the local maximum)
            start = index
            best_index = index
            while index + 1 < len(bins) and bins[index + 1][1] >= threshold - 3:
                index += 1
                if bins[index][1] > bins[best_index][1]:
                    best_index = index
            end = index
            bandwidth = max(1, end - start + 1) * (
                bins[1][0] - bins[0][0] if len(bins) > 1 else 1)
            peak = Peak(
                frequency_hz=bins[best_index][0],
                power_db=bins[best_index][1],
                bandwidth_hz=int(bandwidth),
            )
            label, note = SpectrumScanner.label_for(peak.frequency_hz)
            peak.label, peak.note = label, note
            peaks.append(peak)
            index += 1

        peaks.sort(key=lambda item: -item.power_db)
        return peaks[:max_peaks]

    @staticmethod
    def label_for(frequency_hz: int) -> Tuple[str, str]:
        """Return a human label for a frequency.

        Args:
            frequency_hz: the peak frequency.

        Returns:
            A ``(label, note)`` pair; both empty when nothing matches.
        """
        for name, low, high, note in KNOWN_SIGNALS:
            if low <= frequency_hz <= high:
                return name, note
        return "", ""

    # -- output ------------------------------------------------------------ #
    def write_outputs(self, sweep: Sweep, raw_csv: Path) -> None:
        """Write the JSON summary, a waterfall CSV and an ASCII overview.

        Args:
            sweep: the completed sweep.
            raw_csv: the raw rtl_power file (kept for reprocessing).
        """
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary = self.output_dir / f"summary_{sweep.band}_{stamp}.json"
        summary.write_text(json.dumps(sweep.as_dict(), indent=2) + "\n")
        self.logger.ok("summary: %s", summary.name)

        # Normalised waterfall (0-100 scale) for quick comparison and plotting
        if sweep.bins:
            lowest = min(power for _hz, power in sweep.bins)
            highest = max(power for _hz, power in sweep.bins)
            span = max(0.001, highest - lowest)
            waterfall = self.output_dir / f"waterfall_{sweep.band}_{stamp}.csv"
            with waterfall.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["frequency_mhz", "power_db", "relative_percent"])
                for frequency, power in sweep.bins:
                    writer.writerow([round(frequency / 1e6, 4), round(power, 2),
                                     round((power - lowest) / span * 100, 2)])
            self.logger.debug("waterfall: %s", waterfall.name)

        # ASCII overview so a sweep is readable over SSH
        print()
        self.render_ascii(sweep)

        if self.database is not None:
            try:
                self.database.event(
                    "sdr_scanner", "spectrum",
                    f"{sweep.band}: {len(sweep.peaks)} peak(s), floor "
                    f"{sweep.noise_floor_db:.1f} dB over {sweep.coverage_mhz} MHz",
                    "INFO", data={"band": sweep.band, "peaks": len(sweep.peaks),
                                  "floor_db": round(sweep.noise_floor_db, 2)})
            except Exception as exc:  # pragma: no cover
                self.logger.debug("event insert failed: %s", exc)

    def render_ascii(self, sweep: Sweep, width: int = 76, height: int = 12) -> None:
        """Render a compact ASCII spectrum view of the sweep.

        Args:
            sweep: the sweep to draw.
            width: character width of the plot.
            height: character height of the plot.
        """
        if not sweep.bins:
            return
        powers = [power for _hz, power in sweep.bins]
        lowest, highest = min(powers), max(powers)
        span = max(1.0, highest - lowest)

        # Down-sample into `width` columns
        step = max(1, len(sweep.bins) // width)
        columns: List[float] = []
        for index in range(0, len(sweep.bins), step):
            chunk = [power for _hz, power in sweep.bins[index:index + step]]
            columns.append(max(chunk))
        columns = columns[:width]

        grid = [[" " for _ in range(len(columns))] for _ in range(height)]
        for column, power in enumerate(columns):
            level = int((power - lowest) / span * (height - 1))
            for row in range(level + 1):
                grid[height - 1 - row][column] = "█" if row < level else "▄"

        print(colour(f"  {sweep.band}: {sweep.start_hz / 1e6:.3f} - "
                     f"{sweep.stop_hz / 1e6:.3f} MHz "
                     f"(floor {sweep.noise_floor_db:.1f} dB, span {span:.1f} dB)", "bold"))
        for row in grid:
            print("  " + "".join(row))
        axis = f"  {sweep.start_hz / 1e6:.3f}".ljust(len(columns) // 2) + \
               f"{sweep.stop_hz / 1e6:.3f} MHz"
        print(colour(axis, "dim"))

        if sweep.peaks:
            print(colour("\n  strongest peaks", "bold"))
            print(f"    {'MHz':>10}  {'dB':>7}  {'BW':>9}  LABEL")
            for peak in sweep.peaks[:12]:
                bandwidth = f"{peak.bandwidth_hz / 1000:.0f} kHz"
                print(f"    {peak.frequency_mhz:>10.3f}  {peak.power_db:>7.1f}  "
                      f"{bandwidth:>9}  {peak.label or '—'}"
                      f"{'  (' + peak.note + ')' if peak.note else ''}")
        print()

    def survey(self, bands: Sequence[str], duration: int, integration: int,
               threshold_db: float) -> List[Sweep]:
        """Sweep several bands in turn.

        Args:
            bands: band preset names.
            duration: seconds per band.
            integration: seconds per integration row.
            threshold_db: peak threshold over the noise floor.

        Returns:
            The completed sweeps.
        """
        sweeps: List[Sweep] = []
        for index, band in enumerate(bands, start=1):
            self.logger.info("[%d/%d] sweeping %s", index, len(bands), band)
            sweeps.append(self.sweep(band, duration=duration, integration=integration,
                                     threshold_db=threshold_db))
            if index < len(bands):
                time.sleep(1)
        return sweeps

    def write_survey(self, sweeps: Sequence[Sweep]) -> Path:
        """Write a combined survey report.

        Args:
            sweeps: the completed sweeps.

        Returns:
            Path of the JSON report.
        """
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = self.output_dir / f"survey_{stamp}.json"
        payload = {
            "version": VERSION,
            "generated": now_iso(),
            "host": os.uname().nodename,
            "device": sweeps[0].device if sweeps else "",
            "bands": [sweep.as_dict() for sweep in sweeps],
            "occupancy": {
                sweep.band: {
                    "peaks": len(sweep.peaks),
                    "floor_db": round(sweep.noise_floor_db, 2),
                    "strongest_db": round(max((peak.power_db for peak in sweep.peaks),
                                              default=sweep.noise_floor_db), 2),
                }
                for sweep in sweeps
            },
        }
        report.write_text(json.dumps(payload, indent=2) + "\n")
        self.logger.ok("survey written to %s", report)
        return report

    def list_devices(self) -> int:
        """Print the SDR devices found on the system.

        Returns:
            Process exit code (3 when nothing was found).
        """
        devices = self.sdr_devices()
        if not devices:
            self.logger.warn("no SDR device detected")
            self.logger.info("plug in an RTL-SDR or HackRF, then check: lsusb | grep -i -e rtl -e sdr")
            return 3
        print()
        print(f"  {'DEVICE':<28}{'KIND':<14}{'USB ID':<12}DETAIL")
        print("  " + "─" * 74)
        for device in devices:
            print(f"  {device.get('name', 'unknown')[:26]:<28}"
                  f"{device.get('kind', 'sdr'):<14}{device.get('usb_id', ''):<12}"
                  f"{device.get('detail', '')}")
        print()
        return 0

    def list_bands(self) -> int:
        """Print the band presets.

        Returns:
            Process exit code.
        """
        print()
        print(f"  {'BAND':<12}{'START':>12}{'STOP':>14}{'BIN':>10}  NOTE")
        print("  " + "─" * 96)
        for name, preset in BANDS.items():
            print(f"  {name:<12}{preset['start'] / 1e6:>10.3f} MHz"
                  f"{preset['stop'] / 1e6:>12.3f} MHz{preset['bin'] / 1e3:>8.1f} kHz  "
                  f"{preset['note'][:44]}")
        print()
        return 0


def presets_needed(start_hz: int, stop_hz: int, bin_hz: int) -> bool:
    """Return True when a sweep spans more than one tuner step.

    Args:
        start_hz: start frequency.
        stop_hz: stop frequency.
        bin_hz: bin width.

    Returns:
        True when rtl_power will have to hop, which can miss short signals.
    """
    del bin_hz  # the tuning limit is a property of the dongle, not the bin width
    return (stop_hz - start_hz) > 2_400_000


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="sdr_scanner.py",
        description="RF spectrum survey with an RTL-SDR (receive only)",
        epilog="receive only - see docs/LEGAL.md about what may be listened to")
    parser.add_argument("--version", action="version", version=f"sdr_scanner {VERSION}")
    parser.add_argument("--band", default="ism433",
                        help=f"band preset ({', '.join(BANDS)}) or 'custom' with --start/--stop")
    parser.add_argument("--bands", default="",
                        help="comma-separated list of presets to sweep in sequence")
    parser.add_argument("--start", type=float, default=0.0,
                        help="custom start frequency in MHz")
    parser.add_argument("--stop", type=float, default=0.0,
                        help="custom stop frequency in MHz")
    parser.add_argument("--bin", type=float, default=0.0,
                        help="custom bin width in kHz")
    parser.add_argument("--duration", type=int, default=30,
                        help="seconds per band (default: 30)")
    parser.add_argument("--integration", type=int, default=2,
                        help="seconds averaged per integration row (default: 2)")
    parser.add_argument("--threshold", type=float, default=8.0,
                        help="dB above the noise floor that counts as a peak (default: 8)")
    parser.add_argument("--gain", default=None,
                        help="tuner gain in dB or 'auto' (default: from cyberdeck.conf)")
    parser.add_argument("--ppm", type=int, default=None,
                        help="frequency correction in parts per million")
    parser.add_argument("--list-devices", action="store_true",
                        help="show the SDR devices found, then exit")
    parser.add_argument("--list-bands", action="store_true",
                        help="show the band presets, then exit")
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    parser.add_argument("--from-service", action="store_true",
                        help="quiet, service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="only log warnings and errors")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the spectrum scanner.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 success, 1 failure, 3 no SDR, 4 no data.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("sdr_scanner",
                    level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("SDR spectrum scanner", f"v{VERSION}")

    scanner = SpectrumScanner(config, logger)

    if args.list_devices:
        return scanner.list_devices()
    if args.list_bands:
        return scanner.list_bands()

    if args.ppm is not None:
        scanner.ppm = args.ppm
    if args.start and args.stop:
        args.band = "custom"

    if not scanner.require_sdr():
        return 3

    raw_bin = int((args.bin or 12.5) * 1000)
    bands: List[str]
    if args.bands:
        bands = [band.strip() for band in args.bands.split(",") if band.strip()]
        for band in bands:
            if band not in BANDS:
                start, stop = parse_custom_band(band)
                if start is None:
                    logger.error("unknown band: %s", band)
                    logger.info("valid presets: %s", ", ".join(BANDS))
                    return 2
                BANDS[band] = {"start": start, "stop": stop, "bin": raw_bin,
                               "note": "custom range"}
    else:
        bands = [args.band]

    sweeps: List[Sweep] = []
    if args.band == "custom" and args.start and args.stop:
        sweeps.append(scanner.sweep(
            "custom", duration=args.duration, integration=args.integration,
            start_hz=int(args.start * 1e6), stop_hz=int(args.stop * 1e6),
            bin_hz=raw_bin or 12_500, threshold_db=args.threshold, gain=args.gain))
    else:
        sweeps = scanner.survey(bands, args.duration, args.integration, args.threshold)

    if not sweeps or not any(sweep.bins for sweep in sweeps):
        logger.error("no spectrum data was captured")
        logger.info("check that the dongle is not in use (rtl_test -t) and try again")
        return 4

    scanner.write_survey(sweeps)

    if args.json:
        print(json.dumps({
            "version": VERSION,
            "device": sweeps[0].device,
            "bands": [sweep.as_dict() for sweep in sweeps],
        }, indent=2))
        return 0

    total_peaks = sum(len(sweep.peaks) for sweep in sweeps)
    logger.ok("survey complete: %d band(s), %d peak(s)", len(sweeps), total_peaks)
    labelled = [peak for sweep in sweeps for peak in sweep.peaks if peak.label]
    if labelled:
        print(colour("  identified signals", "bold"))
        for peak in labelled[:10]:
            print(f"    {peak.frequency_mhz:>10.3f} MHz  {peak.power_db:>6.1f} dB  {peak.label}")
        print()
    print(f"  data directory: {scanner.output_dir}\n")
    return 0


def parse_custom_band(specification: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse a ``start-stop`` band specification in MHz.

    Args:
        specification: e.g. ``"430-440"``.

    Returns:
        A ``(start_hz, stop_hz)`` tuple, or ``(None, None)`` when unparseable.
    """
    match = re.match(r"^\s*([\d.]+)\s*[-:]\s*([\d.]+)\s*$", specification)
    if not match:
        return None, None
    start = float(match.group(1))
    stop = float(match.group(2))
    if stop <= start:
        return None, None
    return int(start * 1e6), int(stop * 1e6)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
