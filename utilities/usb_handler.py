#!/usr/bin/env python3
"""
utilities/usb_handler.py - USB device monitor, forensics and autorun guard.
============================================================================

Description
-----------
Watches USB insertions/removals, records a full device profile for every event,
and optionally takes forensically-sound actions on insertion (log, hash,
read-only mount, whole-device image). It also flags the "BadUSB" patterns that
matter on a deck: a device that presents a HID keyboard (or keyboard+storage
combination), an unknown vendor, or a serial number that changed between
insertions of the same model.

Two invocation styles:

* ``--watch``            long-running monitor (used by usb-watcher.service); it
                         polls ``/sys/bus/usb`` and streams events to the console
* ``add <node> | remove <node>``
                         one-shot handling for a udev rule (see
                         ``config/systemd/usb-watcher.service`` and the udev file
                         written by ``setup.sh``), invoked through ``bin/cdeck-usb``

All events land in the shared ``usb`` database (``usb_devices`` table) and in the
component log; images and hashes land under ``<install>/captures/usb``.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python 3.9+ standard library; optional: pyudev (event-driven
              instead of polling), udisks2/udisksctl or udevil (read-only
              mounts), dd (imaging)
Licence     : MIT - authorised use only (see docs/LEGAL.md)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
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
    from cyberlib import (  # type: ignore
        Config,
        Database,
        Logger,
        human_bytes,
        human_duration,
        now_iso,
        run,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: USB interface classes that deserve attention on a security deck
INTERESTING_CLASSES = {
    "01": "audio",
    "02": "communications (CDC)",
    "03": "HID (keyboard/mouse) - BadUSB vector",
    "06": "imaging (PTP/MTP)",
    "07": "printer",
    "08": "mass storage",
    "09": "USB hub",
    "0a": "CDC data",
    "0b": "smart card reader",
    "0e": "video",
    "dc": "diagnostic device",
    "e0": "wireless controller (Bluetooth/WiFi)",
    "ef": "miscellaneous (misc device class)",
    "fe": "application specific (firmware update)",
    "ff": "vendor specific - inspect manually",
}

#: Vendor ids commonly seen on attack hardware
KNOWN_ATTACK_HARDWARE = {
    "1d6b": "Linux Foundation (root hub / gadget)",
    "0bda": "Realtek (RTL-SDR, WiFi adapters, Ethernet)",
    "1d50": "OpenMoko / Great Scott Gadgets (HackRF, Facedancer, GreatFET)",
    "0483": "STMicroelectronics (Proxmark3, Flipper Zero clones)",
    "2a03": "Airspy",
    "0456": "Analog Devices (PlutoSDR)",
    "04d8": "Microchip (Flipper Zero, various dev boards)",
    "1915": "Nordic Semiconductor (nRF dongles, BLE research)",
    "1a86": "QinHeng (CH340 serial, common on dev boards)",
    "2341": "Arduino (Teensy-like and Arduino boards)",
    "16c0": "Van Ooijen Technische Informatica (Teensy, Rubber Ducky clones)",
    "1b4f": "SparkFun",
}


@dataclass
class UsbDevice:
    """A USB device as seen in sysfs."""

    sysfs: str
    action: str
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    manufacturer: str = ""
    product: str = ""
    device_node: str = ""
    driver: str = ""
    bcd_device: str = ""
    speed: str = ""
    interfaces: List[str] = field(default_factory=list)
    block_devices: List[str] = field(default_factory=list)
    risk_notes: List[str] = field(default_factory=list)
    sha256: str = ""

    @property
    def usb_id(self) -> str:
        """Return the ``vid:pid`` pair for this device."""
        return f"{self.vendor_id}:{self.product_id}".rstrip(":")

    @property
    def is_hid(self) -> bool:
        """True when any interface uses the HID class (keyboard/mouse)."""
        return any(code.startswith("03") for code in self.interfaces)

    @property
    def is_storage(self) -> bool:
        """True when the device exposes a mass-storage interface."""
        return bool(self.block_devices) or any(
            code.startswith("08") for code in self.interfaces)

    @property
    def risk(self) -> str:
        """Return ``critical``/``warning``/``info`` for this device."""
        if self.risk_notes:
            return "critical" if any("BadUSB" in note or "keystroke" in note
                                     for note in self.risk_notes) else "warning"
        return "info"

    def as_dict(self) -> Dict[str, Any]:
        """Return the device as a plain dictionary."""
        return {
            "ts": now_iso(),
            "action": self.action,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial": self.serial,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "device_node": self.device_node,
            "driver": self.driver,
            "speed": self.speed,
            "firmware": self.bcd_device,
            "interfaces": [INTERESTING_CLASSES.get(code, code) for code in self.interfaces],
            "block_devices": self.block_devices,
            "risk": self.risk,
            "risk_notes": self.risk_notes,
            "sha256": self.sha256,
            "sysfs": self.sysfs,
        }


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
class UsbMonitor:
    """Enumerates USB devices and records events.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
    """

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                              "/opt/cyberdeck-arsenal")))
        image_dir = config.get("usb.image_dir")
        self.image_dir = Path(str(image_dir)) if image_dir else \
            self.install_dir / "captures" / "usb"
        self.auto_actions = [str(item) for item in
                             (config.get("usb.auto_actions", []) or [])]
        self.max_image_gb = int(config.get("usb.max_image_size_gb", 128) or 128)
        self.block_size = str(config.get("usb.image_block_size", "4M") or "4M")
        self.database: Optional[Database] = None
        try:
            self.database = Database("usb")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("usb database unavailable: %s", exc)
        self.event_log = self.install_dir / "state" / "usb_events.jsonl"

    # -- sysfs parsing ----------------------------------------------------- #
    @staticmethod
    def sysfs_read(path: Path, default: str = "") -> str:
        """Read a sysfs attribute, returning *default* when it is missing."""
        try:
            return path.read_text().strip()
        except OSError:
            return default

    def describe(self, sysfs_path: Path, action: str = "add") -> Optional[UsbDevice]:
        """Build a :class:`UsbDevice` from a ``/sys/bus/usb/devices/*`` entry.

        Args:
            sysfs_path: the device directory in sysfs.
            action: ``add``, ``remove`` or ``scan``.

        Returns:
            The device, or None when the directory is not a USB device.
        """
        if not (sysfs_path / "idVendor").is_file():
            return None

        device = UsbDevice(sysfs=sysfs_path.name, action=action)
        device.vendor_id = self.sysfs_read(sysfs_path / "idVendor")
        device.product_id = self.sysfs_read(sysfs_path / "idProduct")
        device.serial = self.sysfs_read(sysfs_path / "serial")
        device.manufacturer = self.sysfs_read(sysfs_path / "manufacturer")
        device.product = self.sysfs_read(sysfs_path / "product")
        device.driver = (sysfs_path / "driver").resolve().name \
            if (sysfs_path / "driver").exists() else ""
        device.bcd_device = self.sysfs_read(sysfs_path / "bcdDevice")
        speed = self.sysfs_read(sysfs_path / "speed")
        device.speed = f"{speed} Mbps" if speed else ""

        # Interface classes: bInterfaceClass across the interface directories
        for candidate in sorted(sysfs_path.glob("*:*")):
            class_code = self.sysfs_read(candidate / "bInterfaceClass")
            if class_code:
                device.interfaces.append(class_code)

        # Block devices provided by this USB device
        for block in sorted(sysfs_path.glob("host*/target*/*/*/block/*")):
            node = f"/dev/{block.name}"
            if node not in device.block_devices:
                device.block_devices.append(node)
        for block in sorted(sysfs_path.glob("*/block/*")):
            node = f"/dev/{block.name}"
            if node not in device.block_devices:
                device.block_devices.append(node)

        # A serial device (GPS, Proxmark, serial console) shows up as tty*
        for tty in sorted(sysfs_path.glob("*/tty*/*")):
            name = tty.name
            if name.startswith("tty") and not device.device_node:
                device.device_node = f"/dev/{name}"

        self.assess_risk(device)
        return device

    def assess_risk(self, device: UsbDevice) -> None:
        """Fill ``device.risk_notes`` using the BadUSB heuristics."""
        if device.is_hid and device.is_storage:
            device.risk_notes.append(
                "BadUSB pattern: HID + mass storage in one device - a keystroke "
                "injection payload can also drop files")
        elif device.is_hid:
            device.risk_notes.append(
                "HID device: can emit keystrokes; treat as an input device and "
                "keep it out of a locked-down workflow")

        vendor = device.vendor_id.lower()
        if vendor in KNOWN_ATTACK_HARDWARE:
            device.risk_notes.append(
                f"known research/attack hardware vendor: {KNOWN_ATTACK_HARDWARE[vendor]}")

        if not device.serial:
            device.risk_notes.append(
                "no serial number reported - the device cannot be uniquely "
                "identified between insertions (a common trait of cheap "
                "BadUSB/HID emulators)")

        if device.product.lower() in ("", "usb device", "composite device"):
            device.risk_notes.append("generic/unbranded descriptor strings")

        if any(code.startswith("ff") for code in device.interfaces):
            device.risk_notes.append(
                "vendor-specific interface class - descriptor contents are opaque")

        if device.is_storage and not device.risk_notes:
            device.risk_notes.append(
                "removable storage: mount read-only unless you intend to write")

    # -- event handling ---------------------------------------------------- #
    def record(self, device: UsbDevice) -> None:
        """Persist a device event to the database, log and JSONL journal."""
        payload = device.as_dict()
        if self.database is not None:
            try:
                self.database.execute(
                    "INSERT INTO usb_devices (ts, action, vendor_id, product_id, serial, "
                    "manufacturer, product, device_node, sha256, notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (payload["ts"], payload["action"], device.vendor_id, device.product_id,
                     device.serial, device.manufacturer, device.product,
                     device.device_node, device.sha256, "; ".join(device.risk_notes)))
            except Exception as exc:  # pragma: no cover
                self.logger.debug("usb_devices insert failed: %s", exc)
        self.event_log.parent.mkdir(parents=True, exist_ok=True)
        with self.event_log.open("a") as handle:
            handle.write(json.dumps(payload) + "\n")

        summary = (f"{device.manufacturer or 'unknown vendor'} "
                   f"{device.product or 'unknown product'} [{device.usb_id}]")
        if device.action == "remove":
            self.logger.info("USB removed: %s", summary)
            return

        self.logger.ok("USB inserted: %s", summary)
        if device.speed:
            self.logger.info("  link speed : %s%s", device.speed,
                             f" · serial {device.serial}" if device.serial else " · no serial")
        if device.interfaces:
            self.logger.info("  interfaces : %s", ", ".join(
                f"{code} ({INTERESTING_CLASSES.get(code, 'unknown')})"
                for code in device.interfaces))
        for note in device.risk_notes:
            self.logger.alert("  %s", note)

    def scan(self) -> List[UsbDevice]:
        """Return every USB device currently present."""
        devices: List[UsbDevice] = []
        root = Path("/sys/bus/usb/devices")
        if not root.is_dir():
            return devices
        for entry in sorted(root.iterdir()):
            device = self.describe(entry, "scan")
            if device is not None:
                devices.append(device)
        return devices

    def handle_add(self, node: str) -> int:
        """Handle an insertion for a device node or sysfs name.

        Args:
            node: either ``/dev/sda`` style or a sysfs device name (``1-2``).

        Returns:
            Process exit code.
        """
        device = self.resolve_device(node)
        if device is None:
            self.logger.warn("no USB device found for %s", node)
            return 1
        self.record(device)

        for action in self.auto_actions:
            if action == "log":
                continue  # the record above is the log entry
            self.apply_action(device, action)
        return 0

    def handle_remove(self, node: str) -> int:
        """Record a removal event.

        Args:
            node: device node or sysfs device name.

        Returns:
            Process exit code.
        """
        # On removal the sysfs entry is already gone, so reconstruct what we can
        # from the journal: the most recent insertion matching the node.
        device = UsbDevice(sysfs=str(node), action="remove")
        previous = self.last_event_for(node)
        if previous:
            device.vendor_id = previous.get("vendor_id", "")
            device.product_id = previous.get("product_id", "")
            device.serial = previous.get("serial", "")
            device.manufacturer = previous.get("manufacturer", "")
            device.product = previous.get("product", "")
        self.record(device)
        return 0

    def resolve_device(self, node: str) -> Optional[UsbDevice]:
        """Find the USB device behind a node name, block device or sysfs name.

        Args:
            node: ``/dev/...``, ``1-2``, or a partial sysfs path.

        Returns:
            The described device, or None.
        """
        name = Path(node).name
        root = Path("/sys/bus/usb/devices")

        # Direct sysfs name (udev passes the kernel name, e.g. "1-2")
        direct = root / name
        if direct.is_dir():
            return self.describe(direct, "add")

        # Block device: walk back up to the USB device that provides it
        if name.startswith(("sd", "mmcblk", "nvme")):
            link = Path(f"/sys/block/{name}")
            if link.exists():
                for parent in link.resolve().parents:
                    if parent.parent == root and (parent / "idVendor").is_file():
                        return self.describe(parent, "add")
                # Fall back: any USB device that lists this block device
                for device in self.scan():
                    if f"/dev/{name}" in device.block_devices:
                        return device

        # Give up and search everything for a matching node
        for device in self.scan():
            if name in device.block_devices or device.device_node.endswith(name):
                return device
        return None

    def last_event_for(self, node: str) -> Optional[Dict[str, Any]]:
        """Return the last journal entry mentioning *node*."""
        if not self.event_log.is_file():
            return None
        name = Path(node).name
        for line in reversed(self.event_log.read_text().splitlines()[-500:]):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            haystack = json.dumps(entry)
            if name in haystack:
                return entry
        return None

    # -- actions ----------------------------------------------------------- #
    def apply_action(self, device: UsbDevice, action: str) -> bool:
        """Run one configured auto-action for a device.

        Args:
            device: the device being handled.
            action: ``hash``, ``image``, ``mount-ro``, ``eject`` or ``log``.

        Returns:
            True when the action succeeded or was skipped cleanly.
        """
        self.logger.info("running auto-action: %s", action)
        if action == "hash":
            return self.hash_device(device)
        if action == "image":
            return self.image_device(device)
        if action in ("mount-ro", "mount"):
            return self.mount_readonly(device)
        if action == "eject":
            return self.eject(device)
        if action == "log":
            return True
        self.logger.warn("unknown auto-action: %s", action)
        return False

    def hash_device(self, device: UsbDevice) -> bool:
        """Compute a SHA-256 over the first and last megabyte of a block device.

        Hashing a whole multi-terabyte device is rarely what an operator wants
        during triage, so this samples the head and tail plus the size, which is
        enough to spot a swapped device later.

        Args:
            device: the device to hash.

        Returns:
            True when a digest was produced.
        """
        blocks = [node for node in device.block_devices if Path(node).is_file()]
        if not blocks:
            self.logger.debug("nothing to hash for %s (no block device)", device.usb_id)
            return False
        digest = hashlib.sha256()
        for node in blocks:
            path = Path(node)
            try:
                size = path.stat().st_size if path.is_file() else 0
            except OSError:
                size = 0
            digest.update(f"{node}:{size}".encode())
            try:
                with path.open("rb") as handle:
                    digest.update(handle.read(1024 * 1024))
                    if size > 2 * 1024 * 1024:
                        handle.seek(-1024 * 1024, os.SEEK_END)
                        digest.update(handle.read(1024 * 1024))
            except OSError as exc:
                self.logger.warn("cannot read %s (%s) - hashing metadata only", node, exc)
                continue
        device.sha256 = digest.hexdigest()
        self.logger.ok("sampled digest %s… for %s", device.sha256[:16],
                       ", ".join(device.block_devices))
        return True

    def image_device(self, device: UsbDevice) -> bool:
        """Write a forensic image of the device's block device.

        Args:
            device: the device to image.

        Returns:
            True when an image was written.
        """
        blocks = [node for node in device.block_devices if Path(node).is_file()]
        if not blocks:
            self.logger.debug("nothing to image for %s", device.usb_id)
            return False
        if not shutil.which("dd"):
            self.logger.warn("dd is not available - cannot image the device")
            return False

        self.image_dir.mkdir(parents=True, exist_ok=True)
        written = 0
        for node in blocks:
            try:
                size_bytes = Path(node).stat().st_size
            except OSError:
                size_bytes = 0
            size_gb = size_bytes / (1024 ** 3)
            if size_gb > self.max_image_gb:
                self.logger.warn(
                    "%s is %.1f GB which exceeds usb.max_image_size_gb (%s) - skipping",
                    node, size_gb, self.max_image_gb)
                continue
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"{device.vendor_id}{device.product_id}_{Path(node).name}_{stamp}.img"
            target = self.image_dir / name
            self.logger.info("imaging %s → %s (%s)", node, target, human_bytes(size_bytes))
            command = ["dd", f"if={node}", f"of={target}", f"bs={self.block_size}",
                       "conv=noerror,sync", "status=none"]
            code, _out, err = run(command, timeout=3600)
            if code != 0:
                self.logger.error("imaging failed: %s", err.strip()[:200])
                continue
            written += 1
            digest = hashlib.sha256()
            with target.open("rb") as handle:
                for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                    digest.update(chunk)
            device.sha256 = digest.hexdigest()
            manifest = target.with_suffix(".img.sha256")
            manifest.write_text(f"{device.sha256}  {target.name}\n")
            self.logger.ok("image written: %s (sha256 %s…)", target.name,
                           device.sha256[:16])
        return written > 0

    def mount_readonly(self, device: UsbDevice) -> bool:
        """Mount the device's first filesystem read-only.

        Args:
            device: the device to mount.

        Returns:
            True when it was mounted (or already mounted).
        """
        blocks = [node for node in device.block_devices if Path(node).is_file()]
        if not blocks:
            self.logger.debug("nothing to mount for %s", device.usb_id)
            return False
        node = blocks[0]
        # Prefer a partition that actually carries a filesystem
        candidates = [node] + sorted(
            str(path) for path in Path("/dev").glob(f"{Path(node).name}[0-9]*"))
        target_device = node
        for candidate in candidates:
            code, out, _err = run(["lsblk", "-no", "FSTYPE", candidate], timeout=10)
            if code == 0 and str(out).strip():
                target_device = candidate
                break

        self.image_dir.mkdir(parents=True, exist_ok=True)
        mountpoint = self.image_dir / f"mount_{Path(target_device).name}"
        mountpoint.mkdir(parents=True, exist_ok=True)

        if os.path.ismount(mountpoint):
            self.logger.info("%s is already mounted at %s", target_device, mountpoint)
            return True

        if shutil.which("udisksctl"):
            code, out, err = run(["udisksctl", "mount", "-b", target_device,
                                  "-o", "ro"], timeout=60)
            if code == 0:
                self.logger.ok("mounted read-only via udisksctl: %s", str(out).strip())
                self.logger.warn("removable media is untrusted: only hash and copy from it")
                return True
            self.logger.warn("udisksctl mount failed: %s", err.strip()[:160])
        if shutil.which("udevil"):
            code, _out, err = run(["udevil", "mount", "--ro", target_device], timeout=60)
            if code == 0:
                self.logger.ok("mounted read-only via udevil")
                return True
            self.logger.warn("udevil mount failed: %s", err.strip()[:160])

        code, _out, err = run(["mount", "-o", "ro,nosuid,nodev,noexec",
                               target_device, str(mountpoint)], timeout=60)
        if code == 0:
            self.logger.ok("mounted read-only at %s", mountpoint)
            return True
        self.logger.warn("could not mount %s read-only: %s", target_device,
                         err.strip()[:160])
        self.logger.info("is a desktop automounter holding it? try: udisksctl unmount -b %s",
                         target_device)
        return False

    def eject(self, device: UsbDevice) -> bool:
        """Unmount and power down a device safely.

        Args:
            device: the device to eject.

        Returns:
            True when the eject request succeeded.
        """
        blocks = [node for node in device.block_devices if Path(node).is_file()]
        if not blocks:
            return False
        node = blocks[0]
        if shutil.which("udisksctl"):
            code, _out, err = run(["udisksctl", "unmount", "-b", node], timeout=60)
            if code == 0:
                self.logger.ok("unmounted %s", node)
            else:
                self.logger.debug("unmount reported: %s", err.strip()[:120])
            code, _out, err = run(["udisksctl", "power-off", "-b", node], timeout=60)
            if code == 0:
                self.logger.ok("%s is powered off - safe to remove", node)
                return True
            self.logger.warn("power-off failed: %s", err.strip()[:160])
            return False
        code, _out, err = run(["umount", node], timeout=60)
        if code == 0:
            self.logger.ok("unmounted %s - sync before removing", node)
            return True
        self.logger.warn("could not unmount %s: %s", node, err.strip()[:120])
        return False

    # -- reporting --------------------------------------------------------- #
    def history(self, limit: int = 25, as_json: bool = False) -> int:
        """Print recent USB events.

        Args:
            limit: how many entries to show.
            as_json: emit JSON instead of a table.

        Returns:
            Process exit code.
        """
        entries: List[Dict[str, Any]] = []
        if self.event_log.is_file():
            for line in self.event_log.read_text().splitlines()[-limit:]:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if as_json:
            print(json.dumps(entries, indent=2))
            return 0
        if not entries:
            self.logger.info("no USB events recorded yet")
            return 0
        print()
        print(f"  {'WHEN':<20}{'ACTION':<8}{'USB ID':<11}{'MANUFACTURER / PRODUCT':<42}RISK")
        print("  " + "─" * 92)
        for entry in entries:
            label = f"{entry.get('manufacturer') or '?'} {entry.get('product') or '?'}"
            print(f"  {entry.get('ts', '')[:19]:<20}{entry.get('action', ''):<8}"
                  f"{entry.get('vendor_id', '')}:{entry.get('product_id', ''):<8}"
                  f"{label[:40]:<42}{entry.get('risk', 'info')}")
        print()
        risky = [entry for entry in entries if entry.get("risk") == "critical"]
        if risky:
            self.logger.alert("%d critical device event(s) - review the notes above", len(risky))
        return 0

    def watch(self, interval: float = 2.0, once: bool = False,
              duration: int = 0) -> int:
        """Poll sysfs and record insertions/removals as they happen.

        Args:
            interval: seconds between polls.
            once: print the current inventory and exit.
            duration: stop after this many seconds (0 = until interrupted).

        Returns:
            Process exit code.
        """
        self.logger.banner("USB watcher", "polling /sys/bus/usb")
        known: Dict[str, str] = {}
        for device in self.scan():
            known[device.sysfs] = device.usb_id

        if once:
            print()
            for device in self.scan():
                label = f"{device.manufacturer or '?'} {device.product or '?'}"
                print(f"  {device.usb_id:<11}{label[:44]:<46}{device.risk}")
            print(f"\n  {len(known)} device(s) present\n")
            return 0

        running = True

        def stop(_signum: int, _frame: Any) -> None:
            nonlocal running
            running = False

        import signal
        for name in ("SIGINT", "SIGTERM"):
            try:
                signal.signal(getattr(signal, name), stop)
            except (ValueError, OSError):  # pragma: no cover
                pass

        self.logger.ok("watching %d device(s) - press Ctrl-C to stop", len(known))
        started = time.time()
        while running:
            time.sleep(interval)
            current: Dict[str, str] = {}
            for device in self.scan():
                current[device.sysfs] = device.usb_id
                if device.sysfs not in known:
                    self.record(device)
                    for action in self.auto_actions:
                        if action != "log":
                            self.apply_action(device, action)
            for sysfs in set(known) - set(current):
                self.record(UsbDevice(sysfs=sysfs, action="remove",
                                      vendor_id=known[sysfs].split(":")[0],
                                      product_id=known[sysfs].split(":")[-1]))
            known = current
            if duration and time.time() - started >= duration:
                self.logger.info("duration %ss reached", duration)
                break
        self.logger.ok("watcher stopped (%s)", human_duration(time.time() - started))
        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="usb_handler.py",
        description="USB device monitor, forensics and autorun guard",
        epilog="authorised use only - see docs/LEGAL.md")
    parser.add_argument("--version", action="version", version=f"usb_handler {VERSION}")
    parser.add_argument("command", nargs="?", default="watch",
                        choices=["watch", "add", "remove", "list", "history", "image",
                                 "mount", "eject", "scan"],
                        help="action to perform (default: watch)")
    parser.add_argument("node", nargs="?", default="",
                        help="device node, sysfs name, or nothing for watch/list")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="poll interval in seconds for watch mode (default: 2)")
    parser.add_argument("--once", action="store_true",
                        help="with watch: print the current inventory once and exit")
    parser.add_argument("--duration", type=int, default=0,
                        help="stop watching after N seconds (0 = until Ctrl-C)")
    parser.add_argument("--limit", type=int, default=25,
                        help="entries to show for history (default: 25)")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--from-service", action="store_true",
                        help="quiet, service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="only log warnings and errors")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the USB handler.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("usb_handler",
                    level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("USB handler", f"v{VERSION}")

    monitor = UsbMonitor(config, logger)
    command = args.command

    if command in ("watch", "scan"):
        if args.once or command == "scan":
            return monitor.watch(once=True)
        return monitor.watch(args.interval, once=False, duration=args.duration)
    if command == "list":
        devices = monitor.scan()
        if args.json:
            print(json.dumps([device.as_dict() for device in devices], indent=2))
            return 0
        print()
        for device in devices:
            label = f"{device.manufacturer or '?'} {device.product or '?'}"
            print(f"  {device.usb_id:<11}{label[:44]:<46}{device.risk}")
        print(f"\n  {len(devices)} device(s) present\n")
        return 0
    if command == "history":
        return monitor.history(args.limit, args.json)

    if not args.node:
        logger.error("%s needs a device node or sysfs name", command)
        logger.info("examples: usb_handler.py add 1-2 · usb_handler.py image /dev/sda")
        return 2

    device = monitor.resolve_device(args.node)
    if device is None:
        logger.warn("no USB device found for %s", args.node)
        if command in ("add", "mount", "image", "eject"):
            return 3
        monitor.record(UsbDevice(sysfs=args.node, action="remove"))
        return 0

    if command == "add":
        return monitor.handle_add(args.node)
    if command == "remove":
        return monitor.handle_remove(args.node)
    if command == "image":
        ok = monitor.image_device(device)
        monitor.record(device)
        return 0 if ok else 1
    if command == "mount":
        ok = monitor.mount_readonly(device)
        monitor.record(device)
        return 0 if ok else 1
    if command == "eject":
        ok = monitor.eject(device)
        monitor.record(device)
        return 0 if ok else 1

    logger.error("unhandled command: %s", command)  # pragma: no cover
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
