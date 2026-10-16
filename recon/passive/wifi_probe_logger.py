#!/usr/bin/env python3
"""
wifi_probe_logger.py - passive WiFi probe request logger
========================================================

Description
-----------
Puts a monitor-mode interface into promiscuous capture and records every probe
request seen: timestamp, source MAC, vendor (OUI lookup), the SSID being probed
for, signal strength and channel. Results go into ``data/probes.db`` with
de-duplication, so repeated probes from the same device update a single row
while still tracking:

    * how many times a device was seen
    * the strongest signal ever observed (a proxy for "how close is it")
    * the full set of SSIDs the device has probed for (its "preferred network
      list" - a surprisingly good identifier and a classic way to geolocate a
      device from public pwned-network databases)

Privacy note: probe requests are personal data under UK/EU GDPR. Only run this
in an environment where you have a lawful basis and documented authorisation.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; scapy (passive capture); root; a monitor-mode adapter
Licence     : MIT - passive reception only

Usage
-----
    sudo cdeck probes --duration 60
    sudo python3 recon/passive/wifi_probe_logger.py --continuous --hop
    python3 recon/passive/wifi_probe_logger.py --stats
    python3 recon/passive/wifi_probe_logger.py --json --duration 30
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
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
        C, Config, Database, Hardware, Logger, OuiLookup, colour, deps, now_iso,
        require_root, run,
    )
except ImportError as exc:
    print(f"wifi_probe_logger: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Channels worth cycling through on 2.4 GHz plus the common 5 GHz ones
DEFAULT_CHANNELS: Tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                     36, 40, 44, 48, 100, 104, 108, 112, 116, 149, 153, 157, 161)


@dataclass
class DeviceProfile:
    """Aggregated view of a device seen in probe requests."""

    mac: str
    vendor: str = "Unknown"
    first_seen: str = ""
    last_seen: str = ""
    times_seen: int = 0
    strongest_rssi: Optional[int] = None
    ssids: List[str] = None  # type: ignore[assignment]
    channels: List[int] = None  # type: ignore[assignment]
    randomised: bool = False

    def __post_init__(self) -> None:
        """Initialise mutable defaults."""
        if self.ssids is None:
            self.ssids = []
        if self.channels is None:
            self.channels = []

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for --json output."""
        return {
            "mac": self.mac, "vendor": self.vendor,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "times_seen": self.times_seen, "strongest_rssi": self.strongest_rssi,
            "ssids": self.ssids, "channels": self.channels,
            "randomised": self.randomised,
        }


class ProbeLogger:
    """Captures and stores WiFi probe requests."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None,
                 interface: Optional[str] = None) -> None:
        """Prepare capture state, the database and the OUI lookup."""
        self.config = config or Config().load()
        self.logger = logger or Logger("wifi_probe_logger",
                                       str(self.config.get("general.log_level", "INFO")))
        self.interface = interface or self._pick_interface()
        self.oui = OuiLookup()
        self.db = Database("probes", logger=self.logger)
        self.profiles: Dict[str, DeviceProfile] = {}
        self.lock = threading.Lock()
        self.running = False
        self.probes_seen = 0
        self.devices_alerted: set = set()
        self.baseline_devices: set = set()
        self._load_baseline()

    # -- setup -------------------------------------------------------------- #
    def _pick_interface(self) -> Optional[str]:
        """Choose the monitor interface: configured first, then any monitor-capable NIC."""
        configured = str(self.config.get("network.monitor_interface", "") or "")
        candidates = [i.name for i in Hardware.monitor_capable()]
        if configured in candidates:
            return configured
        # A monitor-mode interface is named something like wlan1mon
        for iface in candidates + [i.name for i in Hardware.wifi_interfaces()]:
            if "mon" in iface:
                return iface
        return candidates[0] if candidates else None

    def _load_baseline(self) -> None:
        """Load previously seen MACs so the first run does not storm alerts."""
        try:
            for row in self.db.query("SELECT source_mac FROM devices"):
                self.baseline_devices.add(str(row["source_mac"]).lower())
            if self.baseline_devices:
                self.logger.info(f"loaded {len(self.baseline_devices)} known device(s) from the database")
        except sqlite3.Error as exc:
            self.logger.debug(f"could not load baseline: {exc}")

    def ensure_monitor_mode(self) -> bool:
        """Put the interface into monitor mode (or verify it already is)."""
        if not self.interface:
            self.logger.error("no wireless interface available for probe logging")
            self.logger.info("attach a monitor-capable adapter (see cdeck hardware)")
            return False
        if "mon" in self.interface:
            self.logger.debug(f"{self.interface} already looks like a monitor interface")
            return True
        if deps.have("airmon-ng"):
            code, out, _ = run(["airmon-ng", "start", self.interface], timeout=30)
            if code == 0:
                # airmon-ng renames the interface (usually wlanXmon)
                code, listing, _ = run(["iw", "dev"], timeout=10)
                for line in (listing or "").splitlines():
                    if "Interface" in line:
                        candidate = line.split()[-1]
                        if candidate.endswith("mon") or candidate != self.interface:
                            self.logger.ok(f"monitor interface: {candidate}")
                            self.interface = candidate
                            return True
            self.logger.debug(f"airmon-ng output: {(out or '')[:200]}")
        # Manual fallback
        run(["ip", "link", "set", self.interface, "down"], timeout=10)
        code, _, err = run(["iw", self.interface, "set", "type", "monitor"], timeout=10)
        run(["ip", "link", "set", self.interface, "up"], timeout=10)
        if code != 0:
            self.logger.error(f"could not enable monitor mode on {self.interface}: {err.strip()}")
            self.logger.info("check that the adapter supports monitor mode: cdeck hardware")
            return False
        self.logger.ok(f"{self.interface} set to monitor mode")
        return True

    # -- capture ------------------------------------------------------------ #
    def start(self, hop: bool = False, channels: Sequence[int] = DEFAULT_CHANNELS) -> bool:
        """Start sniffing (blocking in the calling thread unless threaded)."""
        if os.geteuid() != 0:
            self.logger.error("packet capture requires root: sudo cdeck probes")
            return False
        try:
            from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap, sniff  # type: ignore
        except ImportError:
            self.logger.error("scapy is not installed (pip install scapy)")
            return False

        if not self.ensure_monitor_mode():
            return False

        if hop:
            threading.Thread(target=self._hop_channels, args=(channels,),
                             name="channel-hopper", daemon=True).start()

        self.running = True
        self.logger.info(f"listening for probe requests on {self.interface} "
                         f"(Ctrl-C to stop)")

        def handler(packet: Any) -> None:
            try:
                if not packet.haslayer(Dot11ProbeReq):
                    return
                source = str(packet[Dot11].addr2 or "").lower()
                if not source or source == "ff:ff:ff:ff:ff:ff":
                    return
                ssid = ""
                element = packet.getlayer(Dot11Elt)
                while element is not None:
                    if element.ID == 0:
                        try:
                            ssid = element.info.decode(errors="replace")
                        except AttributeError:
                            ssid = ""
                        break
                    element = element.payload.getlayer(Dot11Elt) if hasattr(element, "payload") else None
                rssi = None
                if packet.haslayer(RadioTap):
                    try:
                        rssi = int(packet[RadioTap].dBm_AntSignal)
                    except (AttributeError, TypeError):
                        rssi = None
                channel = None
                if packet.haslayer(Dot11):
                    try:
                        channel = int(getattr(packet[Dot11], "channel", 0)) or None
                    except (TypeError, ValueError):
                        channel = None
                self.record(source, ssid, rssi, channel)
            except Exception as exc:  # noqa: BLE001 - never let the sniffer die
                self.logger.debug(f"probe parse error: {exc}")

        try:
            # stop_filter gives us a clean way out of a blocking sniff()
            sniff(iface=self.interface, prn=handler, store=False,
                  stop_filter=lambda _packet: not self.running,
                  monitor=True)
        except KeyboardInterrupt:
            self.logger.info("capture interrupted by operator")
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"capture failed: {exc}")
            self.logger.info("try: sudo airmon-ng check kill && sudo airmon-ng start "
                             f"{self.interface}")
            return False
        finally:
            self.running = False
            self.flush()
        return True

    def _hop_channels(self, channels: Sequence[int], dwell: float = 0.35) -> None:
        """Cycle the monitor interface through *channels* while capturing."""
        while self.running:
            for channel in channels:
                if not self.running:
                    break
                if deps.have("iw"):
                    run(["iw", "dev", self.interface, "set", "channel", str(channel)], timeout=4)
                elif deps.have("iwconfig"):
                    run(["iwconfig", self.interface, "channel", str(channel)], timeout=4)
                time.sleep(dwell)

    # -- storage ------------------------------------------------------------ #
    def record(self, mac: str, ssid: str, rssi: Optional[int], channel: Optional[int]) -> None:
        """Store one probe request sighting, de-duplicating per device."""
        timestamp = now_iso()
        randomised = self.oui.is_randomised(mac)
        vendor = self.oui.vendor(mac)
        with self.lock:
            profile = self.profiles.get(mac)
            is_new = profile is None
            if is_new:
                profile = DeviceProfile(mac=mac, vendor=vendor, first_seen=timestamp,
                                        randomised=randomised)
                self.profiles[mac] = profile
            profile.last_seen = timestamp
            profile.times_seen += 1
            if rssi is not None and (profile.strongest_rssi is None or rssi > profile.strongest_rssi):
                profile.strongest_rssi = rssi
            if ssid and ssid not in profile.ssids:
                profile.ssids.append(ssid)
                profile.ssids = profile.ssids[-50:]
            if channel and channel not in profile.channels:
                profile.channels.append(channel)
        self.probes_seen += 1

        # Raw sighting row (kept for movement pattern analysis)
        try:
            self.db.execute(
                "INSERT INTO probe_requests (ts, source_mac, vendor, ssid, rssi, channel, random_mac) "
                "VALUES (?,?,?,?,?,?,?)",
                (timestamp, mac, vendor, ssid, rssi, channel, int(randomised)))
        except sqlite3.Error as exc:
            self.logger.debug(f"could not insert probe row: {exc}")

        # Aggregated device row (the useful view)
        try:
            self.db.upsert("devices", ["source_mac"], {
                "source_mac": mac, "vendor": vendor, "first_seen": profile.first_seen,
                "last_seen": timestamp, "times_seen": profile.times_seen,
                "strongest_rssi": profile.strongest_rssi,
                "probed_ssids": json.dumps(profile.ssids),
                "risk": "unknown",
            })
        except sqlite3.Error as exc:
            self.logger.debug(f"could not upsert device row: {exc}")

        display_ssid = ssid or "<wildcard>"
        self.logger.info(f"{mac} ({vendor[:24]}) → '{display_ssid}' "
                         f"{f'{rssi} dBm' if rssi is not None else 'RSSI n/a'}"
                         f"{' [random MAC]' if randomised else ''}")

        self._maybe_alert(profile, is_new)

    def _maybe_alert(self, profile: DeviceProfile, is_new: bool) -> None:
        """Raise an alert for new or persistent devices worth attention."""
        if not is_new or profile.mac in self.devices_alerted:
            return
        self.devices_alerted.add(profile.mac)
        first_run = self.probes_seen <= 3
        if first_run or profile.mac in self.baseline_devices:
            return
        try:
            self.db.event("wifi_probe_logger", "device",
                          f"new WiFi device {profile.mac} ({profile.vendor})",
                          "INFO", profile.as_dict())
        except sqlite3.Error:
            pass
        # A strong signal plus a known SSID is the interesting case: someone is
        # standing near the deck with a device that wants to join a network.
        if profile.strongest_rssi is not None and profile.strongest_rssi > -55:
            self.logger.alert(f"strong-signal device nearby: {profile.mac} "
                              f"({profile.strongest_rssi} dBm)")

    def flush(self) -> None:
        """Persist any pending state and checkpoint the database."""
        try:
            self.db.conn.commit()
        except sqlite3.Error:
            pass

    def stop(self) -> None:
        """Stop the capture loop."""
        self.running = False

    # -- reporting ---------------------------------------------------------- #
    def statistics(self) -> Dict[str, Any]:
        """Return summary statistics for the current session and the database."""
        with self.lock:
            session = {
                "interface": self.interface,
                "probes_this_session": self.probes_seen,
                "devices_this_session": len(self.profiles),
                "randomised_devices": sum(1 for p in self.profiles.values() if p.randomised),
            }
        database: Dict[str, Any] = {}
        try:
            row = self.db.query_one("SELECT COUNT(*) AS probes, "
                                    "COUNT(DISTINCT source_mac) AS devices FROM probe_requests")
            database = dict(row) if row else {}
            top_ssids = self.db.query(
                "SELECT ssid, COUNT(*) AS n FROM probe_requests "
                "WHERE ssid IS NOT NULL AND ssid != '' "
                "GROUP BY ssid ORDER BY n DESC LIMIT 10")
            database["top_ssids"] = [(r["ssid"], r["n"]) for r in top_ssids]
            strongest = self.db.query(
                "SELECT source_mac, vendor, strongest_rssi FROM devices "
                "WHERE strongest_rssi IS NOT NULL ORDER BY strongest_rssi DESC LIMIT 10")
            database["loudest_devices"] = [dict(r) for r in strongest]
            movement = self.db.query(
                "SELECT source_mac, COUNT(*) AS sightings, MIN(ts) AS first, MAX(ts) AS last "
                "FROM probe_requests GROUP BY source_mac ORDER BY sightings DESC LIMIT 10")
            database["most_active"] = [dict(r) for r in movement]
        except sqlite3.Error as exc:
            database["error"] = str(exc)
        return {"session": session, "database": database}

    def render_statistics(self) -> str:
        """Render statistics as colourised text."""
        stats = self.statistics()
        session = stats["session"]
        database = stats["database"]
        lines = [
            colour(f"  WIFI PROBE LOGGER  ::  {now_iso()}", C.BRIGHT_CYAN),
            "",
            colour("  SESSION", C.BOLD),
            f"  interface            {session['interface'] or 'none'}",
            f"  probes captured      {session['probes_this_session']}",
            f"  unique devices       {session['devices_this_session']} "
            f"({session['randomised_devices']} randomised MACs)",
            "",
            colour("  DATABASE (all time)", C.BOLD),
            f"  total probes         {database.get('probes', 0)}",
            f"  unique devices       {database.get('devices', 0)}",
        ]
        if database.get("top_ssids"):
            lines.append("")
            lines.append(colour("  most probed SSIDs", C.BOLD))
            for ssid, count in database["top_ssids"]:
                lines.append(f"    {count:>6}  {ssid[:60]}")
        if database.get("loudest_devices"):
            lines.append("")
            lines.append(colour("  strongest signals", C.BOLD))
            for row in database["loudest_devices"]:
                lines.append(f"    {row['strongest_rssi']:>5} dBm  {row['source_mac']}  "
                             f"{(row['vendor'] or 'Unknown')[:32]}")
        if database.get("most_active"):
            lines.append("")
            lines.append(colour("  most active devices (movement pattern)", C.BOLD))
            for row in database["most_active"]:
                lines.append(f"    {row['sightings']:>6} sightings  {row['source_mac']}  "
                             f"{row['first'][11:19]} → {row['last'][11:19]}")
        if database.get("error"):
            lines.append("")
            lines.append(colour(f"  database error: {database['error']}", C.BRIGHT_RED))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="wifi_probe_logger.py",
        description="passive WiFi probe request logger (timestamp, MAC, vendor, SSID, RSSI)",
        epilog="Also available as: cdeck probes  |  requires root + monitor mode")
    parser.add_argument("-i", "--interface", default=None, help="monitor interface to use")
    parser.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    parser.add_argument("--continuous", action="store_true",
                        help="run forever (used by probe-logger.service)")
    parser.add_argument("--from-service", action="store_true",
                        help="service-mode logging (no interactive output)")
    parser.add_argument("--hop", action="store_true", help="channel-hop while capturing")
    parser.add_argument("--channels", default=None,
                        help="comma-separated channel list to hop through")
    parser.add_argument("--stats", action="store_true", help="print statistics and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--export-csv", metavar="PATH", default=None,
                        help="export the device table to CSV after capture")
    parser.add_argument("--reset-db", action="store_true",
                        help="delete all probe data before starting (asks nothing: use with care)")
    parser.add_argument("--version", action="version", version=f"wifi_probe_logger {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("wifi_probe_logger", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)),
                    quiet=args.from_service)

    probe_logger = ProbeLogger(config, logger, args.interface)

    if args.reset_db:
        try:
            probe_logger.db.execute("DELETE FROM probe_requests")
            probe_logger.db.execute("DELETE FROM devices")
            logger.warn("probe database cleared")
        except sqlite3.Error as exc:
            logger.error(f"could not clear the database: {exc}")
            return 1

    if args.stats:
        stats = probe_logger.statistics()
        print(json.dumps(stats, indent=2, default=str) if args.json
              else probe_logger.render_statistics())
        probe_logger.db.close()
        return 0

    if not require_root("wifi_probe_logger", logger):
        return 1
    if not probe_logger.interface:
        logger.error("no wireless interface found - attach a monitor-capable adapter")
        return 3

    channels: Sequence[int] = DEFAULT_CHANNELS
    if args.channels:
        try:
            channels = [int(value.strip()) for value in args.channels.split(",") if value.strip()]
        except ValueError:
            logger.warn(f"invalid channel list '{args.channels}' - using the defaults")

    def handle_signal(_signum: int, _frame: Any) -> None:
        logger.info("signal received - stopping capture")
        probe_logger.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if args.duration and not args.continuous:
        def stopper() -> None:
            time.sleep(args.duration or 0)
            logger.info(f"duration reached ({args.duration:.0f}s)")
            probe_logger.stop()
        threading.Thread(target=stopper, daemon=True).start()

    started = probe_logger.start(hop=args.hop or args.continuous, channels=channels)
    if not started:
        probe_logger.db.close()
        return 3

    # Final report
    if args.export_csv:
        try:
            rows = [dict(r) for r in probe_logger.db.query("SELECT * FROM devices ORDER BY last_seen DESC")]
            from cyberlib import write_csv  # type: ignore
            write_csv(Path(args.export_csv), rows)
            logger.ok(f"exported {len(rows)} device(s) to {args.export_csv}")
        except Exception as exc:  # noqa: BLE001
            logger.error(f"CSV export failed: {exc}")

    if args.json:
        print(json.dumps(probe_logger.statistics(), indent=2, default=str))
    else:
        logger.banner("probe logging complete", f"{probe_logger.probes_seen} probes captured")
        print(probe_logger.render_statistics())

    probe_logger.db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
