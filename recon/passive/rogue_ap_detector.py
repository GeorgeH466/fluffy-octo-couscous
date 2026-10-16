#!/usr/bin/env python3
"""
rogue_ap_detector.py - rogue AP and evil twin detection
=======================================================

Description
-----------
Compares the current WiFi landscape against a saved "known good" baseline and
alerts on anything that looks like a rogue access point:

    * a BSSID that has never been seen before
    * a trusted SSID suddenly broadcast by a different BSSID (classic evil twin)
    * an open or WEP network impersonating a WPA2 SSID (encryption downgrade)
    * a big channel change on a known BSSID (legitimate APs do this rarely)
    * a BSSID whose vendor/OUI differs from the baseline vendor
    * an unusually strong signal on a BSSID first seen far away (sticky honeypot)

Baseline management is explicit, because it should be a deliberate act:

    cdeck rogue baseline save      # record the current landscape as known-good
    cdeck rogue baseline show      # inspect the baseline
    cdeck rogue baseline clear     # forget the baseline
    cdeck rogue scan                # one-shot comparison
    sudo cdeck rogue --watch        # continuous monitoring (service mode)

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; iw or nmcli for scanning; root for a full scan
Licence     : MIT - passive scanning only

Usage
-----
    sudo python3 recon/passive/rogue_ap_detector.py --baseline save
    sudo python3 recon/passive/rogue_ap_detector.py --scan
    sudo python3 recon/passive/rogue_ap_detector.py --watch --from-service
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent.parent / "lib",
    Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")) / "lib",
]
for _candidate in _LIB_CANDIDATES:
    if (_candidate / "cyberlib.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

try:
    from cyberlib import (  # type: ignore
        C, Alerts, Config, Database, Hardware, Logger, OuiLookup, colour, deps,
        now_iso, run, write_json,
    )
except ImportError as exc:
    print(f"rogue_ap_detector: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Alert severities by finding type
FINDING_SEVERITY: Dict[str, str] = {
    "evil-twin": "CRITICAL",
    "encryption-downgrade": "CRITICAL",
    "new-bssid": "WARNING",
    "vendor-change": "WARNING",
    "channel-change": "INFO",
    "signal-jump": "INFO",
}


@dataclass
class AccessPoint:
    """An access point seen in a scan."""

    bssid: str
    ssid: str = "<hidden>"
    channel: Optional[int] = None
    signal_dbm: Optional[int] = None
    encryption: str = "unknown"
    vendor: str = "Unknown"
    trusted: bool = False
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    sightings: int = 1

    @property
    def open_network(self) -> bool:
        """True when the network uses no encryption."""
        return self.encryption.upper() in ("OPEN", "NONE", "")

    def as_dict(self) -> Dict[str, Any]:
        """Serialise the AP."""
        return {
            "bssid": self.bssid, "ssid": self.ssid, "channel": self.channel,
            "signal_dbm": self.signal_dbm, "encryption": self.encryption,
            "vendor": self.vendor, "trusted": self.trusted,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "sightings": self.sightings,
        }


@dataclass
class Finding:
    """A deviation from the baseline."""

    kind: str
    bssid: str
    ssid: str
    detail: str
    severity: str = "WARNING"
    ts: str = field(default_factory=now_iso)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise the finding."""
        return {"kind": self.kind, "bssid": self.bssid, "ssid": self.ssid,
                "detail": self.detail, "severity": self.severity, "ts": self.ts}


class RogueApDetector:
    """Scans, compares against the baseline and raises alerts."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None,
                 interface: Optional[str] = None) -> None:
        """Open the baseline database and prepare scanning."""
        self.config = config or Config().load()
        self.logger = logger or Logger("rogue_ap_detector",
                                       str(self.config.get("general.log_level", "INFO")))
        self.interface = interface or self._pick_interface()
        self.oui = OuiLookup()
        self.db = Database("baseline", logger=self.logger)
        self.alerts = Alerts("rogue_ap_detector", self.config, self.logger)
        self.baseline: Dict[str, AccessPoint] = {}
        self.findings: List[Finding] = []
        self.running = False
        self.alerted: set = set()
        self._load_baseline()

    # -- setup -------------------------------------------------------------- #
    def _pick_interface(self) -> Optional[str]:
        """Pick the interface used for scanning."""
        configured = str(self.config.get("network.primary_interface", "") or "")
        wireless = [i.name for i in Hardware.wifi_interfaces()]
        if configured in wireless:
            return configured
        return wireless[0] if wireless else None

    def _load_baseline(self) -> None:
        """Load the baseline from SQLite."""
        try:
            for row in self.db.query("SELECT * FROM ap_baseline"):
                access_point = AccessPoint(
                    bssid=row["bssid"], ssid=row["ssid"] or "<hidden>",
                    channel=row["channel"], encryption=row["encryption"] or "unknown",
                    vendor=row["vendor"] or "Unknown",
                    trusted=bool(row["trusted"]),
                    first_seen=row["first_seen"], last_seen=row["last_seen"],
                    sightings=int(row["sightings"] or 1))
                self.baseline[access_point.bssid.lower()] = access_point
            if self.baseline:
                self.logger.info(f"baseline loaded: {len(self.baseline)} known AP(s)")
            else:
                self.logger.warn("no baseline yet - run: cdeck rogue baseline save")
        except sqlite3.Error as exc:
            self.logger.debug(f"baseline load failed: {exc}")

    def save_baseline(self, merge: bool = False) -> int:
        """Scan and store the current landscape as the known-good baseline."""
        scan = self.scan()
        if not scan:
            self.logger.error("scan returned no access points - baseline not updated")
            return 0
        if not merge:
            try:
                self.db.execute("DELETE FROM ap_baseline")
                self.baseline.clear()
                self.logger.info("previous baseline cleared (merge=False)")
            except sqlite3.Error as exc:
                self.logger.warn(f"could not clear the baseline: {exc}")
        for access_point in scan:
            access_point.trusted = True
            self.baseline[access_point.bssid.lower()] = access_point
            try:
                self.db.upsert("ap_baseline", ["bssid"], {
                    "bssid": access_point.bssid, "ssid": access_point.ssid,
                    "channel": access_point.channel, "encryption": access_point.encryption,
                    "vendor": access_point.vendor, "first_seen": access_point.first_seen,
                    "last_seen": access_point.last_seen, "sightings": access_point.sightings,
                    "trusted": 1,
                })
            except sqlite3.Error as exc:
                self.logger.debug(f"could not store {access_point.bssid}: {exc}")
        self.logger.ok(f"baseline saved with {len(self.baseline)} access point(s)")
        return len(self.baseline)

    def clear_baseline(self) -> None:
        """Delete the stored baseline."""
        try:
            self.db.execute("DELETE FROM ap_baseline")
            self.baseline.clear()
            self.logger.warn("baseline cleared - the next rogue detection run will alert "
                             "on everything until a new baseline is saved")
        except sqlite3.Error as exc:
            self.logger.error(f"could not clear the baseline: {exc}")

    # -- scanning ----------------------------------------------------------- #
    def scan(self) -> List[AccessPoint]:
        """Scan for access points using iw (preferred) or nmcli."""
        if not self.interface:
            self.logger.error("no wireless interface available for scanning")
            return []

        access_points: List[AccessPoint] = []

        if deps.have("iw"):
            code, out, err = run(["iw", "dev", self.interface, "scan"], timeout=30)
            if code == 0 and out:
                access_points = self._parse_iw(out)
            elif err:
                self.logger.debug(f"iw scan failed: {err.strip()[:160]}")

        if not access_points and deps.have("nmcli"):
            code, out, _ = run(["nmcli", "-t", "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
                                "dev", "wifi", "list"], timeout=25)
            if code == 0 and out:
                access_points = self._parse_nmcli(out)

        if not access_points:
            self.logger.debug("scan produced no results (try as root, or bring the radio up)")

        # Update the sighting history for everything we saw
        for access_point in access_points:
            try:
                self.db.upsert("ap_baseline", ["bssid"], {
                    "bssid": access_point.bssid, "ssid": access_point.ssid,
                    "channel": access_point.channel, "encryption": access_point.encryption,
                    "vendor": access_point.vendor,
                    "first_seen": self.baseline.get(access_point.bssid.lower(),
                                                    access_point).first_seen,
                    "last_seen": access_point.last_seen,
                    "sightings": self.baseline.get(access_point.bssid.lower(),
                                                   access_point).sightings + 1,
                    "trusted": 1 if access_point.bssid.lower() in self.baseline else 0,
                })
            except sqlite3.Error:
                pass
        return access_points

    def _parse_iw(self, text: str) -> List[AccessPoint]:
        """Parse ``iw dev <iface> scan`` output."""
        access_points: List[AccessPoint] = []
        current: Optional[AccessPoint] = None
        frequency: Optional[int] = None
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("BSS "):
                if current:
                    access_points.append(current)
                bssid = line.split()[1].split("(")[0].lower()
                current = AccessPoint(bssid=bssid, vendor=self.oui.vendor(bssid))
                frequency = None
            elif current is None:
                continue
            elif line.startswith("freq:"):
                match = re.search(r"(\d+)", line)
                if match:
                    frequency = int(match.group(1))
                    current.channel = self._freq_to_channel(frequency)
            elif line.startswith("signal:"):
                match = re.search(r"(-?\d+)", line)
                if match:
                    current.signal_dbm = int(match.group(1))
            elif line.startswith("SSID:"):
                current.ssid = line[5:].strip() or "<hidden>"
            elif line.startswith("DS Parameter set"):
                match = re.search(r"channel (\d+)", line)
                if match:
                    current.channel = int(match.group(1))
            elif "RSN:" in line:
                current.encryption = "WPA2/WPA3"
            elif "WPA:" in line:
                current.encryption = current.encryption if "RSN" in current.encryption else "WPA"
            elif line.startswith("capability:"):
                if "Privacy" not in line:
                    current.encryption = "OPEN"
                elif "WEP" in line or "Encryption" in line:
                    current.encryption = "WEP"
        if current:
            access_points.append(current)
        return access_points

    def _parse_nmcli(self, text: str) -> List[AccessPoint]:
        """Parse ``nmcli -t`` output."""
        access_points: List[AccessPoint] = []
        for line in text.splitlines():
            parts = re.split(r"(?<!\\):", line)
            if len(parts) < 5:
                continue
            score = 0
            try:
                score = int(parts[3])
            except ValueError:
                score = 0
            access_points.append(AccessPoint(
                bssid=parts[0].lower(),
                ssid=parts[1].replace("\\:", ":") or "<hidden>",
                channel=int(parts[2]) if parts[2].isdigit() else None,
                signal_dbm=int(score / 2 - 100),
                encryption=parts[4] or "OPEN",
                vendor=self.oui.vendor(parts[0])))
        return access_points

    @staticmethod
    def _freq_to_channel(frequency: int) -> Optional[int]:
        """Convert a frequency in MHz to a channel number."""
        if 2412 <= frequency <= 2484:
            return 14 if frequency == 2484 else (frequency - 2407) // 5
        if 5000 <= frequency <= 5900:
            return (frequency - 5000) // 5
        if 5955 <= frequency <= 7115:
            return (frequency - 5955) // 5 + 1
        return None

    # -- comparison --------------------------------------------------------- #
    def compare(self, access_points: Sequence[AccessPoint]) -> List[Finding]:
        """Compare a scan against the baseline and return new findings."""
        findings: List[Finding] = []
        baseline_by_ssid: Dict[str, List[AccessPoint]] = {}
        for access_point in self.baseline.values():
            baseline_by_ssid.setdefault(access_point.ssid.lower(), []).append(access_point)

        for access_point in access_points:
            known = self.baseline.get(access_point.bssid.lower())

            # 1. Brand new BSSID
            if known is None:
                severity = FINDING_SEVERITY["new-bssid"]
                detail = (f"new access point '{access_point.ssid}' "
                          f"({access_point.bssid}) on channel {access_point.channel} "
                          f"encryption={access_point.encryption} "
                          f"signal={access_point.signal_dbm} dBm vendor={access_point.vendor}")
                findings.append(Finding("new-bssid", access_point.bssid, access_point.ssid,
                                        detail, severity))
                # 1b. Worse: a trusted SSID advertised by a new BSSID = evil twin
                if access_point.ssid.lower() in baseline_by_ssid:
                    twin = baseline_by_ssid[access_point.ssid.lower()][0]
                    findings.append(Finding(
                        "evil-twin", access_point.bssid, access_point.ssid,
                        f"SSID '{access_point.ssid}' is also broadcast by "
                        f"{access_point.bssid} ({access_point.vendor}), which is NOT in the "
                        f"baseline ({twin.bssid}, {twin.vendor}). Encryption "
                        f"{access_point.encryption} vs baseline {twin.encryption}. "
                        f"Signal {access_point.signal_dbm} dBm - possible evil twin/honeypot.",
                        FINDING_SEVERITY["evil-twin"]))
                    # 1c. Encryption downgrade
                    if access_point.open_network and not twin.open_network:
                        findings.append(Finding(
                            "encryption-downgrade", access_point.bssid, access_point.ssid,
                            f"'{access_point.ssid}' is OPEN on {access_point.bssid} but "
                            f"{twin.encryption} on the baseline BSSID {twin.bssid} - "
                            f"credential-harvesting pattern.",
                            FINDING_SEVERITY["encryption-downgrade"]))
                continue

            # 2. Known BSSID but the details changed
            if known.encryption.upper() != access_point.encryption.upper():
                severity = ("CRITICAL" if access_point.open_network
                            else FINDING_SEVERITY["encryption-downgrade"])
                findings.append(Finding(
                    "encryption-downgrade", access_point.bssid, access_point.ssid,
                    f"encryption changed from {known.encryption} to {access_point.encryption}",
                    severity))
            if known.channel and access_point.channel and known.channel != access_point.channel:
                findings.append(Finding(
                    "channel-change", access_point.bssid, access_point.ssid,
                    f"channel changed {known.channel} → {access_point.channel}",
                    FINDING_SEVERITY["channel-change"]))
            if known.vendor != "Unknown" and access_point.vendor != "Unknown" \
                    and known.vendor != access_point.vendor:
                findings.append(Finding(
                    "vendor-change", access_point.bssid, access_point.ssid,
                    f"vendor changed {known.vendor} → {access_point.vendor} "
                    f"(MAC cloned onto different hardware?)",
                    FINDING_SEVERITY["vendor-change"]))
            if known.signal_dbm is not None and access_point.signal_dbm is not None \
                    and access_point.signal_dbm - known.signal_dbm > 25:
                findings.append(Finding(
                    "signal-jump", access_point.bssid, access_point.ssid,
                    f"signal jumped {known.signal_dbm} → {access_point.signal_dbm} dBm "
                    f"- a new transmitter may be advertising the same BSSID",
                    FINDING_SEVERITY["signal-jump"]))

        return findings

    def report(self, findings: Sequence[Finding]) -> None:
        """Log, alert on and persist findings."""
        if not findings:
            self.logger.ok("no deviations from the baseline detected")
            return
        for finding in findings:
            key = f"{finding.kind}:{finding.bssid}"
            already_alerted = key in self.alerted
            if already_alerted and finding.severity != "CRITICAL":
                continue
            self.alerted.add(key)
            message = f"{finding.kind.upper()}: {finding.detail}"
            if finding.severity in ("CRITICAL", "ERROR"):
                self.logger.error(message)
            elif finding.severity == "WARNING":
                self.logger.warn(message)
            else:
                self.logger.info(message)
            try:
                self.db.execute(
                    "INSERT INTO ap_alerts (ts, bssid, ssid, kind, detail) VALUES (?,?,?,?,?)",
                    (finding.ts, finding.bssid, finding.ssid, finding.kind, finding.detail))
            except sqlite3.Error:
                pass
            if bool(self.config.get("alerts.rogue_ap_alert", True)) and not already_alerted:
                self.alerts.send(
                    f"Rogue AP detected: {finding.ssid}",
                    finding.detail[:280], finding.severity)
        self.findings.extend(findings)

    # -- modes -------------------------------------------------------------- #
    def scan_once(self) -> Tuple[List[AccessPoint], List[Finding]]:
        """Perform one scan/compare cycle."""
        access_points = self.scan()
        findings = self.compare(access_points)
        self.report(findings)
        return access_points, findings

    def watch(self, interval: int) -> None:
        """Continuously scan and compare (used by rogue-ap-detector.service)."""
        self.running = True
        self.logger.info(f"rogue AP watch started (interval {interval}s, "
                         f"interface {self.interface})")
        while self.running:
            try:
                access_points, findings = self.scan_once()
                self.logger.debug(f"scan complete: {len(access_points)} AP(s), "
                                  f"{len(findings)} finding(s)")
            except Exception as exc:  # noqa: BLE001
                self.logger.warn(f"scan cycle failed: {exc}")
            # Sleep in small slices so SIGTERM is handled promptly
            slept = 0.0
            while self.running and slept < interval:
                time.sleep(min(1.0, interval - slept))
                slept += 1.0
        self.logger.info("rogue AP watch stopped")

    # -- reporting ---------------------------------------------------------- #
    def render_report(self, access_points: Sequence[AccessPoint],
                      findings: Sequence[Finding]) -> str:
        """Render a colourised text report."""
        lines = [
            colour(f"  ROGUE AP DETECTOR  ::  {now_iso()}", C.BRIGHT_CYAN),
            f"  interface {self.interface or '?'} · baseline {len(self.baseline)} AP(s) · "
            f"visible {len(access_points)} AP(s)",
            "",
            colour("  VISIBLE ACCESS POINTS", C.BOLD),
        ]
        for access_point in sorted(access_points,
                                   key=lambda a: (a.signal_dbm if a.signal_dbm is not None else -999),
                                   reverse=True):
            known = access_point.bssid.lower() in self.baseline
            marker = colour("✔", C.GREEN) if known else colour("?", C.BRIGHT_RED)
            lines.append(f"  {marker} {access_point.signal_dbm if access_point.signal_dbm is not None else '?':>5} dBm  "
                         f"ch{str(access_point.channel or '?'):<3} "
                         f"{access_point.encryption[:9]:<10} {access_point.ssid[:26]:<26} "
                         f"{access_point.bssid}  {access_point.vendor[:20]}")
        if findings:
            lines.append("")
            lines.append(colour("  ⚠ FINDINGS", C.BRIGHT_RED))
            for finding in findings:
                lines.append(f"  [{finding.severity:<8}] {finding.kind:<22} "
                             f"{finding.ssid[:24]:<24} {finding.detail[:70]}")
        else:
            lines.append("")
            lines.append(colour("  no deviations from the baseline", C.GREEN))
        return "\n".join(lines)

    def close(self) -> None:
        """Release handles."""
        try:
            self.db.close()
        except sqlite3.Error:
            pass
        try:
            self.alerts.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="rogue_ap_detector.py",
        description="rogue AP / evil twin detector with explicit baseline management",
        epilog="Also available as: cdeck rogue")
    parser.add_argument("-i", "--interface", default=None, help="wireless interface to scan with")
    parser.add_argument("--scan", action="store_true", help="one scan and comparison")
    parser.add_argument("--watch", action="store_true", help="scan continuously (service mode)")
    parser.add_argument("--from-service", action="store_true", help="service-mode logging")
    parser.add_argument("--interval", type=int, default=None,
                        help="seconds between scans in --watch mode (default from config)")
    parser.add_argument("--baseline", choices=["save", "show", "clear", "merge"], default=None,
                        help="baseline management: save, merge, show or clear")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--version", action="version", version=f"rogue_ap_detector {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("rogue_ap_detector", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)),
                    quiet=args.from_service)

    detector = RogueApDetector(config, logger, args.interface)

    def handle_signal(_signum: int, _frame: Any) -> None:
        logger.info("signal received - stopping the detector")
        detector.running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        if args.baseline == "show":
            if not detector.baseline:
                print("no baseline recorded - run: cdeck rogue baseline save")
                return 0
            if args.json:
                print(json.dumps([a.as_dict() for a in detector.baseline.values()], indent=2))
            else:
                print(colour(f"  BASELINE ({len(detector.baseline)} access points)", C.BOLD))
                for access_point in sorted(detector.baseline.values(), key=lambda a: a.ssid):
                    print(f"  {access_point.ssid[:28]:<30} {access_point.bssid}  "
                          f"ch{str(access_point.channel or '?'):<3} {access_point.encryption:<10} "
                          f"{access_point.vendor[:22]}")
            return 0

        if args.baseline == "clear":
            detector.clear_baseline()
            return 0

        if args.baseline in ("save", "merge"):
            count = detector.save_baseline(merge=(args.baseline == "merge"))
            return 0 if count else 1

        if args.watch:
            interval = args.interval or int(config.get("monitoring.rogue_ap_check_interval", 300))
            detector.watch(interval)
            return 0

        # Default: a single scan + comparison
        access_points, findings = detector.scan_once()
        if args.json:
            print(json.dumps({
                "generated": now_iso(),
                "interface": detector.interface,
                "visible": [a.as_dict() for a in access_points],
                "baseline_size": len(detector.baseline),
                "findings": [f.as_dict() for f in findings],
            }, indent=2))
        else:
            print(detector.render_report(access_points, findings))
        return 0
    except KeyboardInterrupt:
        print()
        return 130
    finally:
        detector.close()


if __name__ == "__main__":
    sys.exit(main())
