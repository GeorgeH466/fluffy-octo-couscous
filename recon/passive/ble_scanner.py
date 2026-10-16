#!/usr/bin/env python3
"""
ble_scanner.py - continuous Bluetooth Low Energy enumeration
============================================================

Description
-----------
Scans for BLE advertisements using the ``bleak`` library, records every device
(name, address, RSSI, advertised services, manufacturer data) into
``data/ble.db`` and flags devices that match known-vulnerable entries in
``data/ble_vulnerability_db.json``.

Why it matters on a deck: BLE is everywhere - trackers, medical devices, locks,
fobs, keyboards - and the advertisement payload alone often leaks enough to
fingerprint the make and model. A rogue tracker following you, or a vulnerable
fob in range, is exactly the kind of thing an operator wants to know about.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; bleak (async BLE); BlueZ; a BLE-capable adapter
Licence     : MIT - passive scanning only

Usage
-----
    cdeck ble --duration 30
    sudo python3 recon/passive/ble_scanner.py --continuous
    python3 recon/passive/ble_scanner.py --list-vulnerable
    python3 recon/passive/ble_scanner.py --json --duration 15
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sqlite3
import sys
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
        C, Config, Database, Hardware, Logger, OuiLookup, colour, deps, now_iso, read_json,
    )
except ImportError as exc:
    print(f"ble_scanner: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Vendor identifiers that appear inside manufacturer-specific advertisement data
MANUFACTURER_IDS: Dict[int, str] = {
    0x0006: "Microsoft", 0x004C: "Apple", 0x0075: "Samsung", 0x0087: "Garmin",
    0x00E0: "Google", 0x0157: "Xiaomi", 0x0171: "Amazon", 0x038F: "Xiaomi",
    0x0499: "Ruuvi", 0x05A7: "Sonos", 0x0385: "Tile", 0x00D2: "Google/Nest",
    0x0134: "Fitbit", 0x004D: "Sony", 0x000F: "Broadcom", 0x0059: "Nordic Semi",
    0x02E5: "Withings", 0x009E: "Bose", 0x0483: "STMicro", 0x01DA: "Adafruit",
    0x03DA: "Govee", 0x02E1: "Dexcom", 0x00C4: "Logitech", 0x012D: "Bragi",
}

#: Service UUIDs that identify common device classes
SERVICE_NAMES: Dict[str, str] = {
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000fd6f-0000-1000-8000-00805f9b34fb": "Exposure Notification",
    "0000fe9a-0000-1000-8000-00805f9b34fb": "Fast Pair",
    "0000feaa-0000-1000-8000-00805f9b34fb": "Eddystone",
    "0000181c-0000-1000-8000-00805f9b34fb": "User Data",
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time",
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART",
}

#: Apple continuity message types seen in manufacturer data
APPLE_TYPES: Dict[int, str] = {
    0x01: "iPhone/iPad nearby", 0x02: "iBeacon", 0x05: "AirDrop", 0x06: "HomeKit",
    0x07: "AirPods", 0x09: "AirPlay Target", 0x0A: "AirPlay Source",
    0x0C: "Handoff", 0x0D: "Tethering Target", 0x0E: "Tethering Source",
    0x0F: "Nearby Action", 0x10: "Nearby Info", 0x12: "Find My (tracker)",
}


@dataclass
class BleDevice:
    """A BLE device and everything we learned about it."""

    address: str
    name: str = ""
    rssi: Optional[int] = None
    manufacturer: str = ""
    manufacturer_data: str = ""
    services: List[str] = field(default_factory=list)
    service_names: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    times_seen: int = 1
    vulnerable: bool = False
    cve_refs: List[str] = field(default_factory=list)
    risk_notes: List[str] = field(default_factory=list)
    device_class: str = "unknown"

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "address": self.address, "name": self.name, "rssi": self.rssi,
            "manufacturer": self.manufacturer, "manufacturer_data": self.manufacturer_data,
            "services": self.services, "service_names": self.service_names,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "times_seen": self.times_seen, "vulnerable": self.vulnerable,
            "cve_refs": self.cve_refs, "risk_notes": self.risk_notes,
            "device_class": self.device_class,
        }


class VulnerabilityDatabase:
    """Loads and queries the bundled BLE vulnerability database."""

    def __init__(self, config: Config, logger: Logger) -> None:
        """Locate the database relative to the install directory and the repo."""
        self.logger = logger
        install = Path(config.get("general.install_dir", "/opt/cyberdeck-arsenal"))
        candidates = [
            install / "data" / "ble_vulnerability_db.json",
            Path(__file__).resolve().parent.parent.parent / "data" / "ble_vulnerability_db.json",
            Path("/opt/cyberdeck-arsenal/data/ble_vulnerability_db.json"),
        ]
        self.entries: List[Dict[str, Any]] = []
        self.version = "unknown"
        for candidate in candidates:
            if candidate.is_file():
                data = read_json(candidate, default={}) or {}
                self.entries = list(data.get("devices", []))
                self.version = str(data.get("version", "unknown"))
                self.logger.debug(f"loaded {len(self.entries)} BLE vulnerability entries "
                                  f"(db v{self.version}) from {candidate}")
                break
        if not self.entries:
            self.logger.debug("no BLE vulnerability database found - vulnerability flagging disabled")

    def check(self, device: BleDevice) -> Tuple[bool, List[str], List[str]]:
        """Return ``(vulnerable, cve_refs, notes)`` for *device*."""
        cves: List[str] = []
        notes: List[str] = []
        haystack = " ".join([device.name, device.manufacturer, device.manufacturer_data,
                             " ".join(device.services), " ".join(device.service_names)]).lower()
        for entry in self.entries:
            match_tokens = [str(token).lower() for token in entry.get("match", [])]
            if not match_tokens:
                continue
            if any(token in haystack for token in match_tokens):
                note = f"{entry.get('device', 'unknown device')}: {entry.get('summary', '')}"
                notes.append(note)
                cves.extend(str(cve) for cve in entry.get("cves", []))
        return bool(notes), sorted(set(cves)), notes

    def list_vulnerable(self) -> str:
        """Render the database as text for `--list-vulnerable`."""
        lines = [colour(f"  BLE VULNERABILITY DATABASE (v{self.version})", C.BOLD),
                 colour(f"  {len(self.entries)} entries", C.DIM), ""]
        for entry in self.entries:
            severity = str(entry.get("severity", "unknown")).upper()
            colour_code = (C.BRIGHT_RED if severity in ("CRITICAL", "HIGH")
                           else C.YELLOW if severity == "MEDIUM" else C.DIM)
            lines.append(f"  {colour(f'[{severity:<8}]', colour_code)} "
                         f"{entry.get('device', 'unknown')}")
            lines.append(f"      match : {', '.join(str(m) for m in entry.get('match', []))}")
            lines.append(f"      issue : {entry.get('summary', '')}")
            if entry.get("cves"):
                lines.append(f"      cves  : {', '.join(str(c) for c in entry['cves'])}")
            if entry.get("mitigation"):
                lines.append(f"      fix   : {entry['mitigation']}")
            lines.append("")
        return "\n".join(lines)


class BleScanner:
    """Async BLE scanner with SQLite persistence and vulnerability flagging."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None) -> None:
        """Prepare the scanner: database, OUI table, vulnerability database."""
        self.config = config or Config().load()
        self.logger = logger or Logger("ble_scanner",
                                       str(self.config.get("general.log_level", "INFO")))
        self.db = Database("ble", logger=self.logger)
        self.oui = OuiLookup()
        self.vuln_db = VulnerabilityDatabase(self.config, self.logger)
        self.devices: Dict[str, BleDevice] = {}
        self.sightings = 0
        self.running = False

    # -- helpers ------------------------------------------------------------ #
    @staticmethod
    def _decode_manufacturer(data: Dict[int, bytes]) -> Tuple[str, str, List[str]]:
        """Return ``(vendor, hex payload, notes)`` for manufacturer data."""
        if not data:
            return "", "", []
        notes: List[str] = []
        company_ids = list(data.keys())
        primary = company_ids[0]
        vendor = MANUFACTURER_IDS.get(primary, f"Company ID 0x{primary:04X}")
        payload = data.get(primary, b"")
        hex_payload = payload.hex()

        # Apple devices pack a continuity message type in the first byte
        if primary == 0x004C and payload:
            continuity_type = payload[0]
            label = APPLE_TYPES.get(continuity_type)
            if label:
                notes.append(f"Apple continuity: {label}")
            # Find My beacons advertise a 0x12 type with a 22-byte payload
            if continuity_type == 0x12 and len(payload) >= 22:
                notes.append("possible Find My / tracker beacon")
        # Samsung SmartThings / Tile / Google Fast Pair hints
        if primary == 0x0075 and payload:
            notes.append("Samsung accessory advertising")
        if primary == 0x0385:
            notes.append("Tile tracker advertising")
        return vendor, hex_payload, notes

    @staticmethod
    def _device_class(name: str, services: Sequence[str], notes: Sequence[str]) -> str:
        """Classify a device from its name, services and advertisement notes."""
        haystack = f"{name} {' '.join(services)} {' '.join(notes)}".lower()
        mapping = (
            (("airpod", "headphone", "buds", "speaker", "soundbar"), "audio"),
            (("watch", "band", "fitbit", "garmin", "whoop"), "wearable"),
            (("heart", "thermometer", "glucose", "dexcom", "oximeter"), "medical"),
            (("tracker", "tile", "find my", "smarttag", "airtag"), "tracker"),
            (("keyboard", "mouse", "hid", "keypad"), "hid-input"),
            (("lock", "august", "noke", "igloohome"), "access-control"),
            (("sensor", "ruuvi", "govee", "environmental"), "sensor"),
            (("fast pair", "google"), "google-device"),
            (("iphone", "ipad", "macbook", "apple"), "apple-device"),
        )
        for needles, label in mapping:
            if any(needle in haystack for needle in needles):
                return label
        return "unknown"

    # -- scanning ------------------------------------------------------------ #
    async def scan(self, duration: Optional[float], continuous: bool) -> None:
        """Run the BLE scan loop until the duration elapses (or forever)."""
        try:
            from bleak import BleakScanner  # type: ignore
        except ImportError:
            self.logger.error("bleak is not installed (pip install bleak)")
            self.logger.info("install it with: /opt/cyberdeck-arsenal/venv/bin/pip install bleak")
            return

        interval = float(self.config.get("monitoring.ble_scan_interval", 30))
        deadline = time.time() + duration if duration else None
        self.running = True

        def callback(device: Any, advertisement: Any) -> None:
            try:
                self.record(device, advertisement)
            except Exception as exc:  # noqa: BLE001 - never break the callback
                self.logger.debug(f"BLE record error: {exc}")

        self.logger.info("BLE scan starting (passive/advertisement-only)")
        try:
            while self.running:
                # A fresh scanner per pass: BlueZ can wedge a long-lived one
                scanner = BleakScanner(detection_callback=callback)
                window = interval if continuous else min(interval, deadline - time.time()
                                                        if deadline else interval)
                if window <= 0:
                    break
                try:
                    await scanner.start()
                    await asyncio.sleep(window)
                    await scanner.stop()
                except Exception as exc:  # noqa: BLE001
                    self.logger.warn(f"scan pass failed: {exc}")
                    self.logger.info("check that bluetooth.service is running and the "
                                     "adapter is not blocked (rfkill list)")
                    await asyncio.sleep(5)
                self.logger.debug(f"scan pass complete: {len(self.devices)} device(s) so far, "
                                  f"{self.sightings} advertisement(s)")
                if deadline and time.time() >= deadline:
                    break
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False
        self.logger.ok(f"BLE scan finished: {len(self.devices)} device(s), "
                       f"{self.sightings} advertisement(s)")

    def record(self, device: Any, advertisement: Any) -> None:
        """Store one advertisement."""
        address = str(getattr(device, "address", "") or "")
        if not address:
            return
        name = str(getattr(device, "name", "") or getattr(advertisement, "local_name", "") or "")
        rssi = getattr(advertisement, "rssi", None) or getattr(device, "rssi", None)
        manufacturer_data = getattr(advertisement, "manufacturer_data", {}) or {}
        service_data = getattr(advertisement, "service_data", {}) or {}
        service_uuids = [str(u).lower() for u in (getattr(advertisement, "service_uuids", []) or [])]
        vendor, manufacturer_hex, notes = self._decode_manufacturer(manufacturer_data)
        service_names = [SERVICE_NAMES.get(uuid, uuid[:8]) for uuid in service_uuids]
        service_names += [SERVICE_NAMES.get(str(u).lower(), str(u)[:8]) for u in service_data]

        timestamp = now_iso()
        existing = self.devices.get(address)
        if existing is None:
            ble_device = BleDevice(address=address, name=name, rssi=rssi,
                                   manufacturer=vendor or self.oui.vendor(address),
                                   manufacturer_data=manufacturer_hex, services=service_uuids,
                                   service_names=sorted(set(service_names)))
            ble_device.device_class = self._device_class(name, service_names, notes)
            ble_device.risk_notes.extend(notes)
            vulnerable, cves, vuln_notes = self.vuln_db.check(ble_device)
            ble_device.vulnerable = vulnerable
            ble_device.cve_refs = cves
            ble_device.risk_notes.extend(vuln_notes)
            self.devices[address] = ble_device
            self._log_new_device(ble_device)
        else:
            existing.last_seen = timestamp
            existing.times_seen += 1
            if rssi is not None:
                existing.rssi = rssi
            if name and not existing.name:
                existing.name = name
            for uuid in service_uuids:
                if uuid not in existing.services:
                    existing.services.append(uuid)
            for service_name in service_names:
                if service_name not in existing.service_names:
                    existing.service_names.append(service_name)
            ble_device = existing

        self.sightings += 1
        self._persist(ble_device, rssi)

    def _log_new_device(self, device: BleDevice) -> None:
        """Log and alert on a newly discovered device."""
        label = device.name or device.manufacturer or "unnamed"
        message = (f"new BLE device {device.address} ({label}) rssi={device.rssi} "
                   f"class={device.device_class}")
        if device.vulnerable:
            self.logger.alert(message + f" ⚠ VULNERABLE: {', '.join(device.cve_refs) or 'see notes'}")
            for note in device.risk_notes:
                self.logger.warn(f"    {note}")
            try:
                self.db.event("ble_scanner", "vulnerability",
                              f"vulnerable BLE device {device.address} ({label})",
                              "ALERT", device.as_dict())
            except sqlite3.Error:
                pass
        elif device.device_class in ("tracker", "apple-device") and device.rssi and device.rssi > -60:
            self.logger.alert(message + " ⚠ tracker-class device nearby")
        else:
            self.logger.info(message)

    def _persist(self, device: BleDevice, rssi: Optional[int]) -> None:
        """Write the device and the sighting to SQLite."""
        try:
            self.db.upsert("ble_devices", ["address"], {
                "address": device.address, "name": device.name,
                "vendor": device.manufacturer or device.manufacturer_data[:16],
                "first_seen": device.first_seen, "last_seen": device.last_seen,
                "times_seen": device.times_seen, "last_rssi": rssi,
                "manufacturer_data": json.dumps({
                    "hex": device.manufacturer_data,
                    "vendor": device.manufacturer,
                    "notes": device.risk_notes,
                }),
                "service_uuids": json.dumps(device.service_names or device.services),
                "vulnerable": int(device.vulnerable),
                "cve_refs": json.dumps(device.cve_refs),
            })
            self.db.execute(
                "INSERT INTO ble_sightings (ts, address, rssi, channel) VALUES (?,?,?,?)",
                (now_iso(), device.address, rssi, None))
        except sqlite3.Error as exc:
            self.logger.debug(f"could not persist {device.address}: {exc}")

    # -- reporting ---------------------------------------------------------- #
    def summary(self) -> Dict[str, Any]:
        """Return a summary of the current session and the database."""
        session = {
            "devices": len(self.devices),
            "sightings": self.sightings,
            "vulnerable": sum(1 for d in self.devices.values() if d.vulnerable),
            "classes": {},
        }
        for device in self.devices.values():
            session["classes"][device.device_class] = session["classes"].get(
                device.device_class, 0) + 1
        database: Dict[str, Any] = {}
        try:
            row = self.db.query_one("SELECT COUNT(*) AS total, "
                                    "SUM(vulnerable) AS vulnerable FROM ble_devices")
            database = dict(row) if row else {}
            strongest = self.db.query(
                "SELECT address, name, last_rssi, vulnerable FROM ble_devices "
                "WHERE last_rssi IS NOT NULL ORDER BY last_rssi DESC LIMIT 10")
            database["strongest"] = [dict(r) for r in strongest]
        except sqlite3.Error as exc:
            database["error"] = str(exc)
        return {"session": session, "database": database}

    def render_summary(self) -> str:
        """Render the session summary as colourised text."""
        summary = self.summary()
        session = summary["session"]
        database = summary["database"]
        lines = [
            colour(f"  BLE SCANNER  ::  {now_iso()}", C.BRIGHT_CYAN),
            "",
            colour("  SESSION", C.BOLD),
            f"  devices discovered   {session['devices']}",
            f"  advertisements       {session['sightings']}",
            f"  vulnerable devices   {session['vulnerable']}",
        ]
        if session["classes"]:
            classes = ", ".join(f"{name}={count}" for name, count in
                                sorted(session["classes"].items(), key=lambda kv: -kv[1]))
            lines.append(f"  device classes       {classes}")
        lines.append("")
        lines.append(colour("  DEVICES", C.BOLD))
        for device in sorted(self.devices.values(), key=lambda d: (not d.vulnerable, d.address)):
            marker = colour("⚠ VULN", C.BRIGHT_RED) if device.vulnerable else "      "
            name = (device.name or device.manufacturer or "unnamed")[:26]
            lines.append(f"  {marker} {device.address:<18} {name:<26} "
                         f"{str(device.rssi):>5} dBm  {device.device_class:<14} "
                         f"x{device.times_seen}")
            for note in device.risk_notes[:2]:
                lines.append(colour(f"            {note[:96]}", C.DIM))
        if database:
            lines.append("")
            lines.append(colour(f"  DATABASE  ({database.get('total', '?')} devices, "
                                f"{database.get('vulnerable', '?')} vulnerable)", C.BOLD))
            for row in database.get("strongest", []):
                flag = colour(" ⚠", C.BRIGHT_RED) if row.get("vulnerable") else ""
                lines.append(f"    {row['last_rssi']:>5} dBm  {row['address']}  "
                             f"{(row['name'] or 'unnamed')[:30]}{flag}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ble_scanner.py",
        description="continuous BLE enumeration with vulnerability flagging",
        epilog="Also available as: cdeck ble")
    parser.add_argument("--duration", type=float, default=None,
                        help="scan for N seconds (default: one interval)")
    parser.add_argument("--continuous", action="store_true", help="scan forever (service mode)")
    parser.add_argument("--from-service", action="store_true", help="service-mode logging")
    parser.add_argument("--list-vulnerable", action="store_true",
                        help="print the vulnerability database and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON summary")
    parser.add_argument("--history", action="store_true",
                        help="show devices recorded in previous sessions")
    parser.add_argument("--version", action="version", version=f"ble_scanner {__version__}")
    return parser.parse_args(argv)


def render_history(scanner: BleScanner) -> str:
    """Render previously recorded BLE devices from the database."""
    try:
        rows = scanner.db.query(
            "SELECT address, name, vendor, last_rssi, times_seen, vulnerable, last_seen "
            "FROM ble_devices ORDER BY last_seen DESC LIMIT 50")
    except sqlite3.Error as exc:
        return colour(f"  database error: {exc}", C.BRIGHT_RED)
    lines = [colour(f"  BLE HISTORY  ({len(rows)} device(s) shown)", C.BOLD), ""]
    for row in rows:
        flag = colour("⚠", C.BRIGHT_RED) if row["vulnerable"] else " "
        lines.append(f"  {flag} {row['address']:<18} {(row['name'] or row['vendor'] or 'unnamed')[:28]:<28} "
                     f"{str(row['last_rssi']):>5} dBm  x{row['times_seen']:<4} "
                     f"{row['last_seen'][11:19]}")
    if not rows:
        lines.append("  no BLE devices recorded yet - run: cdeck ble --duration 30")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("ble_scanner", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)),
                    quiet=args.from_service)

    scanner = BleScanner(config, logger)

    if args.list_vulnerable:
        print(scanner.vuln_db.list_vulnerable())
        scanner.db.close()
        return 0

    if args.history:
        print(render_history(scanner))
        scanner.db.close()
        return 0

    # Pre-flight: is there a usable BLE adapter?
    if not Path("/sys/class/bluetooth").exists():
        logger.warn("no Bluetooth adapter found in /sys/class/bluetooth")
        logger.info("attach a BLE adapter (a £10 CSR8510 dongle works well on a deck)")
        if not args.json:
            print(scanner.render_summary())
        scanner.db.close()
        return 0 if args.duration else 3

    def handle_signal(_signum: int, _frame: Any) -> None:
        logger.info("signal received - stopping BLE scan")
        scanner.running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    duration = args.duration
    if args.continuous and duration is None:
        duration = None
    elif duration is None:
        duration = float(config.get("monitoring.ble_scan_interval", 30))

    try:
        asyncio.run(scanner.scan(duration, args.continuous))
    except KeyboardInterrupt:
        logger.info("BLE scan interrupted")
    finally:
        try:
            scanner.db.conn.commit()
        except sqlite3.Error:
            pass

    if args.json:
        print(json.dumps(scanner.summary(), indent=2, default=str))
    else:
        logger.banner("BLE scan complete",
                      f"{len(scanner.devices)} device(s), {scanner.sightings} advertisement(s)")
        print(scanner.render_summary())
    scanner.db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
