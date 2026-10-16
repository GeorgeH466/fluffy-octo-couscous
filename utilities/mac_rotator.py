#!/usr/bin/env python3
"""
utilities/mac_rotator.py - MAC address rotation and spoofing.
==============================================================

Description
-----------
Rotates the MAC address of one or more interfaces, either once (for the
``mac-rotator.service`` unit) or on a schedule, with an audit trail:

* the *real* hardware address is recorded once in ``state/mac_addresses.json``
  (mode 0600) so ``--restore`` always works, even after many rotations;
* every rotation is written to ``state/mac_rotation.log``, the shared events
  database and the component log;
* ``--vendor`` picks a real OUI out of ``data/oui_database.txt`` so the spoofed
  address is consistent with a plausible device instead of looking random;
* ``--dry-run`` shows exactly what would happen without touching an interface.

Rotating the MAC defeats naive client tracking between visits, but it also
*resets the association*: the interface is briefly down and goes through DHCP
again. On many APs that is logged as a new client.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python 3.9+ standard library; optional: macchanger for a full
              vendor-level spoof, NetworkManager (nmcli) to re-DHCP cleanly
Licence     : MIT - authorised use only (see docs/LEGAL.md)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# --------------------------------------------------------------------------- #
# Shared library
# --------------------------------------------------------------------------- #
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
        OuiLookup,
        now_iso,
        run,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"
MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
VENDOR_NAMES = (
    "Apple", "Samsung", "Intel", "Dell", "HP", "Lenovo", "Cisco", "Netgear",
    "TP-Link", "Asus", "Acer", "Microsoft", "Google", "Xiaomi", "Huawei",
    "Ubiquiti", "Raspberry", "Realtek", "Broadcom", "Qualcomm",
)


@dataclass
class RotationRecord:
    """One change of an interface's hardware address."""

    ts: str
    interface: str
    original: str
    previous: str
    current: str
    vendor: str
    method: str
    duration_ms: int = 0
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """Return the record as a plain dictionary."""
        return {
            "ts": self.ts,
            "interface": self.interface,
            "original": self.original,
            "previous": self.previous,
            "current": self.current,
            "vendor": self.vendor,
            "method": self.method,
            "duration_ms": self.duration_ms,
            "note": self.note,
        }


class MacRotator:
    """Rotates, restores and reports MAC addresses.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
        state_file: where the original addresses are stored.
    """

    def __init__(self, config: Config, logger: Logger,
                 state_file: Optional[Path] = None) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                              "/opt/cyberdeck-arsenal")))
        self.state_file = state_file or (self.install_dir / "state" / "mac_addresses.json")
        self.history_file = self.install_dir / "state" / "mac_rotation.log"
        self.originals: Dict[str, str] = {}
        self.history: List[RotationRecord] = []
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover - database optional
            self.logger.debug("events database unavailable: %s", exc)
        self.load_state()

    # -- state ------------------------------------------------------------- #
    def load_state(self) -> None:
        """Load the recorded original addresses from disk."""
        if not self.state_file.is_file():
            return
        try:
            self.originals = json.loads(self.state_file.read_text())
            self.logger.debug("loaded originals for %d interface(s)", len(self.originals))
        except (json.JSONDecodeError, OSError) as exc:
            self.logger.debug("could not read %s (%s)", self.state_file, exc)
            self.originals = {}

    def save_state(self) -> None:
        """Persist the recorded original addresses (mode 0600)."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(self.originals, indent=2) + "\n")
        try:
            os.chmod(self.state_file, 0o600)
        except OSError:
            pass

    def append_history(self, record: RotationRecord) -> None:
        """Append a record to the rotation journal."""
        self.history.append(record)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        with self.history_file.open("a") as handle:
            handle.write(json.dumps(record.as_dict()) + "\n")
        if self.database is not None:
            try:
                self.database.event(
                    "mac_rotator", "privacy",
                    f"{record.interface}: {record.previous} -> {record.current} "
                    f"({record.vendor})", "INFO", data=record.as_dict())
            except Exception as exc:  # pragma: no cover
                self.logger.debug("event insert failed: %s", exc)

    # -- interface helpers ------------------------------------------------ #
    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """Return True when *mac* looks like a unicast MAC address."""
        if not MAC_PATTERN.match(mac):
            return False
        first = int(mac.split(":")[0], 16)
        return not first & 0x01  # multicast addresses are invalid for an NIC

    @staticmethod
    def current_mac(interface: str) -> Optional[str]:
        """Return the current hardware address of *interface*, or None."""
        path = Path(f"/sys/class/net/{interface}/address")
        try:
            return path.read_text().strip().lower()
        except OSError:
            return None

    @staticmethod
    def interface_exists(interface: str) -> bool:
        """Return True when the interface is present in the kernel."""
        return Path(f"/sys/class/net/{interface}").exists()

    def wireless_interfaces(self) -> List[str]:
        """Return the wireless interfaces on the system."""
        return [iface.name for iface in Hardware.wifi_interfaces()]

    def targets(self, requested: Sequence[str]) -> List[str]:
        """Work out which interfaces to act on.

        Args:
            requested: interfaces named on the command line (may be empty).

        Returns:
            The list of interfaces, preferring the configuration when the
            command line is silent and wireless interfaces when the
            configuration lists none that exist.
        """
        if requested:
            return [iface for iface in requested if self.interface_exists(iface)]

        configured = self.config.get("mac_rotation.interfaces", []) or []
        if isinstance(configured, str):
            configured = [part.strip() for part in configured.split(",") if part.strip()]
        existing = [str(iface) for iface in configured if self.interface_exists(str(iface))]
        if existing:
            return existing

        wireless = self.wireless_interfaces()
        if wireless:
            return wireless
        # Last resort: the configured primary interface if it is real
        primary = str(self.config.get("network.primary_interface", ""))
        return [primary] if primary and self.interface_exists(primary) else []

    # -- address generation ------------------------------------------------ #
    def oui_pool(self) -> List[str]:
        """Return OUI prefixes from the offline vendor database.

        Returns:
            A list of ``AA:BB:CC`` prefixes, empty when the database is missing.
        """
        lookup = OuiLookup()
        table = getattr(lookup, "table", {})
        prefixes = [prefix for prefix in table if MAC_PATTERN.match(prefix + ":00:00:00")]
        return prefixes

    def generate_mac(self, vendor: Optional[str] = None,
                     preserve_oui: bool = False, current: Optional[str] = None) -> str:
        """Generate a MAC address for spoofing.

        Args:
            vendor: vendor name or OUI prefix to use; ``"random"`` or ``None``
                picks a random OUI from the offline database.
            preserve_oui: keep the OUI of *current* and only randomise the NIC
                part (useful when a DHCP reservation or ACL is OUI-based).
            current: the address currently in use.

        Returns:
            A valid unicast MAC address string.
        """
        if preserve_oui and current:
            prefix = current[:8]
        elif vendor and MAC_PATTERN.match(vendor + ":00:00:00"):
            prefix = vendor.upper()
        elif vendor and vendor.lower() not in ("random", "any", ""):
            prefix = self.pick_vendor_prefix(vendor, current)
        else:
            pool = self.oui_pool()
            if pool:
                prefix = random.choice(pool).upper()
            else:
                # Locally administered, one of the few "correct" random forms
                prefix = f"{random.randint(0, 255) & 0xFE | 0x02:02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"

        suffix = [random.randint(0, 255) for _ in range(3)]
        mac = f"{prefix.upper()}:{suffix[0]:02X}:{suffix[1]:02X}:{suffix[2]:02X}"
        if not self.is_valid_mac(mac):  # never hand out a multicast address
            mac = self.generate_mac(None, False, current)
        return mac

    def pick_vendor_prefix(self, vendor: str, current: Optional[str]) -> str:
        """Find an OUI prefix belonging to *vendor*.

        Args:
            vendor: a vendor name or a fragment of one, e.g. ``"apple"``.
            current: the current address (used for a consistent fallback).

        Returns:
            An ``AA:BB:CC`` prefix string.
        """
        lookup = OuiLookup()
        table = getattr(lookup, "table", {})
        matches = [prefix for prefix, name in table.items()
                   if vendor.lower() in str(name).lower()]
        if matches:
            return random.choice(matches)
        # Fall back to any vendor name guess, then to the current OUI
        for prefix, name in table.items():
            if prefix.upper() == vendor.upper():
                return prefix.upper()
        if current:
            return current[:8]
        pool = self.oui_pool()
        return random.choice(pool) if pool else "02:00:00"

    def vendor_of(self, mac: str) -> str:
        """Return the vendor name for a MAC address."""
        try:
            return OuiLookup().vendor(mac)
        except Exception:
            return "unknown"

    # -- privileged operations -------------------------------------------- #
    def set_mac(self, interface: str, mac: str, dry_run: bool = False,
                restart_nm: bool = True) -> bool:
        """Apply a MAC address to an interface.

        Args:
            interface: interface name.
            mac: the address to set.
            dry_run: report what would happen without changing anything.
            restart_nm: bounce NetworkManager so DHCP re-runs with the new MAC.

        Returns:
            True when the address is in place afterwards.
        """
        if not self.is_valid_mac(mac):
            self.logger.error("%s is not a valid unicast MAC address", mac)
            return False

        if dry_run:
            self.logger.info("[dry-run] ip link set dev %s down", interface)
            self.logger.info("[dry-run] ip link set dev %s address %s", interface, mac)
            self.logger.info("[dry-run] ip link set dev %s up", interface)
            return True

        if os.geteuid() != 0:
            self.logger.error("changing a MAC address requires root (use sudo)")
            return False

        started = time.time()
        previous = self.current_mac(interface) or "unknown"

        # Record the true hardware address the first time we touch an interface
        if interface not in self.originals:
            self.originals[interface] = previous
            self.save_state()
            self.logger.info("recorded original address for %s: %s", interface, previous)

        commands = [
            ["ip", "link", "set", "dev", interface, "down"],
            ["ip", "link", "set", "dev", interface, "address", mac],
            ["ip", "link", "set", "dev", interface, "up"],
        ]
        success = True
        for command in commands:
            code, _out, err = run(command, timeout=15)
            if code != 0:
                self.logger.debug("%s failed (%s): %s", " ".join(command), code, err.strip())
                success = False
                break

        applied = self.current_mac(interface)
        method = "ip"
        if not success or applied != mac.lower():
            # Fall back to macchanger, which also handles some stubborn drivers
            if shutil_which("macchanger"):
                self.logger.info("falling back to macchanger for %s", interface)
                run(["ip", "link", "set", "dev", interface, "down"], timeout=10)
                code, _out, err = run(["macchanger", "-m", mac, interface], timeout=20)
                run(["ip", "link", "set", "dev", interface, "up"], timeout=10)
                applied = self.current_mac(interface)
                method = "macchanger"
                if code != 0:
                    self.logger.debug("macchanger failed: %s", err.strip())
            if applied != mac.lower():
                self.logger.error(
                    "%s refused the new address (still %s)", interface, applied or "unknown")
                self.logger.info(
                    "some drivers/APs restore the hardware address; a USB adapter "
                    "with a patched driver is more reliable")
                return False

        if restart_nm:
            self.renew_lease(interface)

        duration = int((time.time() - started) * 1000)
        self.append_history(RotationRecord(
            ts=now_iso(), interface=interface, original=self.originals.get(interface, previous),
            previous=previous, current=applied or mac, vendor=self.vendor_of(applied or mac),
            method=method, duration_ms=duration))
        self.logger.ok("%s: %s → %s (%s, %d ms)",
                       interface, previous, applied, self.vendor_of(applied or mac), duration)
        self.write_runtime_env(interface, mac)
        return True

    def renew_lease(self, interface: str) -> None:
        """Ask the network stack to re-acquire an address on *interface*."""
        if shutil_which("nmcli"):
            code, _out, _err = run(
                ["nmcli", "device", "reapply", interface], timeout=25)
            if code == 0:
                self.logger.info("NetworkManager reapplied the profile on %s", interface)
                return
            # Older NM versions need the connection cycled instead
            code, out, _err = run(
                ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show",
                 "--active"], timeout=20)
            for line in str(out).splitlines():
                name, _, device = line.partition(":")
                if device.strip() == interface:
                    run(["nmcli", "connection", "down", name.strip()], timeout=25)
                    run(["nmcli", "connection", "up", name.strip()], timeout=25)
                    self.logger.info("cycled NetworkManager connection %s", name.strip())
                    return
        if shutil_which("dhcpcd"):
            run(["dhcpcd", "-n", interface], timeout=25)
        elif shutil_which("dhclient"):
            run(["dhclient", "-r", interface], timeout=20)
            run(["dhclient", interface], timeout=25)
        else:
            self.logger.debug("no DHCP client found to renew the lease on %s", interface)

    def write_runtime_env(self, interface: str, mac: str) -> None:
        """Expose the latest rotation for the HUD and shell prompts."""
        target = self.install_dir / "state" / "mac_rotation.env"
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a") as handle:
            handle.write(f"{interface}_mac={mac}\n{interface}_rotated={now_iso()}\n")

    def restore(self, interface: str, dry_run: bool = False) -> bool:
        """Restore the recorded hardware address of *interface*."""
        original = self.originals.get(interface)
        if not original:
            self.logger.warn("no original address recorded for %s", interface)
            self.logger.info("the hardware address is stored the first time it is rotated, "
                             "in %s", self.state_file)
            return False
        if dry_run:
            self.logger.info("[dry-run] restore %s to %s", interface, original)
            return True
        if not self.set_mac(interface, original, dry_run=False):
            return False
        self.logger.ok("%s restored to its original address %s", interface, original)
        return True

    # -- reporting --------------------------------------------------------- #
    def show(self, interfaces: Sequence[str]) -> int:
        """Print the current address of every interface plus its vendor."""
        print()
        header = f"  {'INTERFACE':<14}{'CURRENT MAC':<20}{'ORIGINAL MAC':<20}VENDOR"
        print(header)
        print("  " + "─" * (len(header) - 2))
        for interface in interfaces:
            current = self.current_mac(interface) or "unknown"
            original = self.originals.get(interface, "-")
            spoofed = " (spoofed)" if original not in ("-", current) else ""
            print(f"  {interface:<14}{current:<20}{original:<20}"
                  f"{self.vendor_of(current)}{spoofed}")
        print()
        if self.history:
            print(f"  last rotation: {self.history[-1].ts} "
                  f"({self.history[-1].interface} → {self.history[-1].current})")
        print(f"  journal: {self.history_file}")
        print(f"  state  : {self.state_file}")
        print()
        return 0

    def load_history(self, limit: int = 20) -> List[RotationRecord]:
        """Load the most recent records from the rotation journal."""
        if not self.history_file.is_file():
            return []
        records: List[RotationRecord] = []
        for line in self.history_file.read_text().splitlines()[-limit:]:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(RotationRecord(**{
                key: payload.get(key, "") for key in
                ("ts", "interface", "original", "previous", "current", "vendor",
                 "method", "duration_ms", "note")}))
        return records

    def status(self) -> Dict[str, Any]:
        """Return a JSON-serialisable status document."""
        records = self.load_history(10)
        return {
            "version": VERSION,
            "enabled": bool(self.config.get("mac_rotation.enabled", True)),
            "state_file": str(self.state_file),
            "journal": str(self.history_file),
            "interfaces": [
                {
                    "interface": iface.name,
                    "mac": iface.mac,
                    "vendor": self.vendor_of(iface.mac),
                    "original": self.originals.get(iface.name, ""),
                    "spoofed": bool(self.originals.get(iface.name)
                                    and self.originals[iface.name] != iface.mac),
                }
                for iface in Hardware.interfaces()],
            "recent_rotations": [record.as_dict() for record in records],
        }

    def loop(self, interfaces: Sequence[str], interval: int,
             vendor: Optional[str], preserve_oui: bool, dry_run: bool,
             skip_wired: bool = True) -> int:
        """Rotate every *interval* seconds until interrupted.

        Args:
            interfaces: interfaces to rotate.
            interval: seconds between rotations (minimum 60).
            vendor: vendor filter for the generated addresses.
            preserve_oui: keep each interface's OUI.
            dry_run: show what would happen instead of doing it.
            skip_wired: leave non-wireless interfaces alone.

        Returns:
            Process exit code.
        """
        if interval < 60:
            self.logger.warn("refusing an interval below 60s: %s (a burst of new MACs "
                             "is itself a signature)", interval)
            interval = 60
        self.logger.banner("MAC rotation loop", f"every {interval}s")
        self.logger.warn("press Ctrl-C to stop - each rotation briefly interrupts traffic")

        running = True

        def stop(_signum: int, _frame: Any) -> None:
            nonlocal running
            running = False
            self.logger.info("stopping after the current rotation")

        import signal
        for name in ("SIGINT", "SIGTERM"):
            try:
                signal.signal(getattr(signal, name), stop)
            except (ValueError, OSError):  # pragma: no cover
                pass

        count = 0
        while running:
            for interface in interfaces:
                current = self.current_mac(interface)
                if current is None:
                    self.logger.warn("interface %s disappeared - skipping", interface)
                    continue
                new_mac = self.generate_mac(vendor, preserve_oui, current)
                count += 1
                self.logger.info("rotation #%d on %s", count, interface)
                self.set_mac(interface, new_mac, dry_run)
            if not running:
                break
            self.logger.info("sleeping %ss until the next rotation", interval)
            slept = 0
            while running and slept < interval:
                time.sleep(min(5, interval - slept))
                slept += 5
        self.logger.ok("rotated %d time(s) this session", count)
        return 0


def shutil_which(binary: str) -> Optional[str]:
    """Return the path of *binary* when it is installed.

    Args:
        binary: executable name.

    Returns:
        Absolute path, or None.
    """
    import shutil as _shutil
    return _shutil.which(binary)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="mac_rotator.py",
        description="rotate, spoof and restore interface MAC addresses",
        epilog="authorised use only - see docs/LEGAL.md")
    parser.add_argument("--version", action="version", version=f"mac_rotator {VERSION}")
    parser.add_argument("-i", "--interface", action="append", default=[],
                        help="interface to act on (repeatable; default: wireless)")
    parser.add_argument("--list", "-l", action="store_true",
                        help="show current and original addresses, then exit")
    parser.add_argument("--rotate", "-r", action="store_true",
                        help="rotate the MAC address now (default action)")
    parser.add_argument("--restore", action="store_true",
                        help="restore the recorded hardware address")
    parser.add_argument("--set", dest="set_mac", metavar="MAC", default=None,
                        help="set a specific MAC address")
    parser.add_argument("--vendor", default=None,
                        help="prefer an OUI from this vendor (e.g. apple, intel)")
    parser.add_argument("--preserve-oui", action="store_true",
                        help="keep the current OUI and randomise only the device part")
    parser.add_argument("--interval", type=int, default=0,
                        help="rotate continuously with this many seconds between changes")
    parser.add_argument("--count", type=int, default=1,
                        help="rotate this many times, then exit (default: 1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would change without touching the interface")
    parser.add_argument("--no-restart-network", action="store_true",
                        help="do not bounce NetworkManager / re-run DHCP afterwards")
    parser.add_argument("--history", type=int, default=0, metavar="N",
                        help="show the last N rotations and exit")
    parser.add_argument("--json", action="store_true",
                        help="emit status as JSON (with --list) or results as JSON")
    parser.add_argument("--from-service", action="store_true",
                        help="service-friendly output: no banners, quieter logging")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="only log warnings and errors")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the MAC rotator.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 success, 1 failure, 2 usage, 3 nothing to do.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    # --json means "machine readable stdout": keep every log line out of it
    logger = Logger("mac_rotator",
                    level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not args.from_service and not args.quiet and not args.json:
        logger.banner("MAC rotator", f"v{VERSION}")

    rotator = MacRotator(config, logger)

    # -- history ----------------------------------------------------------- #
    if args.history:
        records = rotator.load_history(args.history)
        if args.json:
            print(json.dumps([record.as_dict() for record in records], indent=2))
            return 0
        if not records:
            logger.info("no rotations recorded yet")
            return 0
        print()
        print(f"  {'WHEN':<20}{'INTERFACE':<12}{'FROM':<20}{'TO':<20}VENDOR")
        for record in records:
            print(f"  {record.ts:<20}{record.interface:<12}{record.previous:<20}"
                  f"{record.current:<20}{record.vendor}")
        print()
        return 0

    interfaces = rotator.targets(args.interface)

    # -- list -------------------------------------------------------------- #
    if args.list:
        if args.json:
            print(json.dumps(rotator.status(), indent=2))
            return 0
        # Reporting is a read-only view: show every interface unless the
        # operator asked for a specific subset.
        reportable = list(interfaces) or [iface.name for iface in Hardware.interfaces()]
        if not reportable:
            logger.warn("no network interfaces found")
            return 3
        return rotator.show(reportable)

    if not interfaces:
        logger.error("no usable interface found")
        logger.info("available: %s", ", ".join(
            iface.name for iface in Hardware.interfaces()) or "none")
        logger.info("pass one explicitly with: --interface <name>")
        return 3

    # -- configuration gate ------------------------------------------------ #
    if not bool(config.get("mac_rotation.enabled", True)) and not (
            args.interface or args.set_mac or args.restore):
        logger.info("mac_rotation.enabled is false in cyberdeck.conf - nothing to do")
        return 0

    if args.vendor and not args.vendor.lower() in ("random", "any"):
        logger.info("preferring addresses from vendor: %s", args.vendor)

    # -- restore ----------------------------------------------------------- #
    if args.restore:
        failures = 0
        for interface in interfaces:
            if not rotator.restore(interface, args.dry_run):
                failures += 1
        if args.json:
            print(json.dumps(rotator.status(), indent=2))
        return 0 if failures == 0 else 1

    # -- specific address -------------------------------------------------- #
    if args.set_mac:
        if not MacRotator.is_valid_mac(args.set_mac):
            logger.error("%s is not a valid unicast MAC address", args.set_mac)
            return 2
        results = [rotator.set_mac(interface, args.set_mac, args.dry_run,
                                   restart_nm=not args.no_restart_network)
                   for interface in interfaces]
        return 0 if all(results) else 1

    # -- continuous rotation ---------------------------------------------- #
    if args.interval:
        return rotator.loop(interfaces, args.interval, args.vendor,
                            args.preserve_oui, args.dry_run)

    # -- one-shot rotation (default and --rotate) -------------------------- #
    results: List[bool] = []
    for interface in interfaces:
        for attempt in range(max(1, args.count)):
            current = rotator.current_mac(interface)
            if current is None:
                logger.warn("interface %s is not present - skipping", interface)
                results.append(False)
                continue
            if rotator.vendor_of(current) == "Randomised (locally administered)":
                logger.debug("%s already has a locally administered address", interface)
            new_mac = rotator.generate_mac(args.vendor, args.preserve_oui, current)
            ok = rotator.set_mac(interface, new_mac, args.dry_run,
                                 restart_nm=not args.no_restart_network)
            results.append(ok)
            if not ok:
                break

    if args.json:
        print(json.dumps({
            "interfaces": interfaces,
            "results": [{"interface": iface, "success": result}
                        for iface, result in zip(interfaces, results)],
            "status": rotator.status(),
        }, indent=2))
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
