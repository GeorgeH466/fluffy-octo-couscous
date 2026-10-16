#!/usr/bin/env python3
"""
main_hud.py - cyberdeck-arsenal main heads-up display
=====================================================

Description
-----------
The primary operator interface: a Textual/rich terminal dashboard that shows,
in one resizable screen:

    * network interface status (link state, MAC, monitor capability)
    * nearby WiFi networks (count, strongest, channel spread, encryption)
    * BLE device count and the most recently seen devices
    * system vitals (CPU, RAM, temperature, battery, disk, load)
    * active TCP/UDP connections and a live packet-rate sparkline
    * VPN / Tor / anonymity posture
    * GPS coordinates when a receiver is present
    * last recon results summary (from the reports directory)
    * scrolling alert feed from the shared alerts database
    * uptime and service state

Missing hardware is handled gracefully: every panel degrades to an explanatory
placeholder instead of raising, so the HUD is useful on a plain laptop too.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib (stdlib + PyYAML/psutil optional); textual+rich for the
              full TUI. Without textual it falls back to a rich live view, and
              without rich it prints a plain status snapshot.
Licence     : MIT - authorised use only, see docs/LEGAL.md

Usage
-----
    cdeck dashboard
    python3 dashboard/main_hud.py --refresh 1.5
    python3 dashboard/main_hud.py --once          # single snapshot, no TUI
    python3 dashboard/main_hud.py --compact       # layout for small screens
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Library import (works from the repo checkout as well as /opt install)
# --------------------------------------------------------------------------- #
_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "lib",
    Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")) / "lib",
    Path("/opt/cyberdeck-arsenal/lib"),
]
for _candidate in _LIB_CANDIDATES:
    if (_candidate / "cyberlib.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

try:
    from cyberlib import (  # type: ignore
        C, Config, Database, Hardware, Logger, OuiLookup, colour, deps,
        human_bytes, human_duration, now_iso, run,
    )
except ImportError as exc:  # pragma: no cover - only when the suite is broken
    print(f"cyberdeck HUD: cannot import cyberlib ({exc}).", file=sys.stderr)
    print("Run the installer first: sudo ./setup.sh", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #
THEMES: Dict[str, Dict[str, str]] = {
    "cyberpunk": {
        "primary": "#00ffd5", "secondary": "#ff79c6", "accent": "#8bd5ff",
        "warning": "#ffb86c", "error": "#ff5555", "ok": "#50fa7b",
        "dim": "#5a6b7a", "panel": "#101418",
    },
    "stealth": {
        "primary": "#7a8b99", "secondary": "#5a6b7a", "accent": "#8a99a8",
        "warning": "#b0a070", "error": "#b07070", "ok": "#8aa070",
        "dim": "#3a444d", "panel": "#0b0e11",
    },
    "matrix": {
        "primary": "#00ff41", "secondary": "#00c030", "accent": "#7dff9b",
        "warning": "#b8ff5c", "error": "#ff6b6b", "ok": "#00ff41",
        "dim": "#0f3d1a", "panel": "#000000",
    },
}


# --------------------------------------------------------------------------- #
# Data collection
# --------------------------------------------------------------------------- #
@dataclass
class WifiNetwork:
    """A single visible access point."""

    bssid: str = "unknown"
    ssid: str = "<hidden>"
    channel: Optional[int] = None
    signal_dbm: Optional[int] = None
    encryption: str = "unknown"
    vendor: str = "Unknown"
    seen_at: str = field(default_factory=now_iso)


@dataclass
class Snapshot:
    """Everything the HUD renders, gathered in one pass."""

    ts: str = field(default_factory=now_iso)
    interfaces: List[Any] = field(default_factory=list)
    wifi: List[WifiNetwork] = field(default_factory=list)
    wifi_error: Optional[str] = None
    ble_count: int = 0
    ble_recent: List[Dict[str, Any]] = field(default_factory=list)
    ble_error: Optional[str] = None
    vitals: Dict[str, Any] = field(default_factory=dict)
    connections: List[Dict[str, str]] = field(default_factory=list)
    connection_count: int = 0
    listening_count: int = 0
    tor_active: bool = False
    vpn_active: bool = False
    vpn_name: str = ""
    gps: Optional[Dict[str, Any]] = None
    last_scan: Optional[Dict[str, Any]] = None
    alerts: List[Dict[str, str]] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    packet_rate: float = 0.0
    uptime_seconds: Optional[float] = None


class Collector:
    """Gathers HUD data. Every method is defensive: never raises to the UI."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None) -> None:
        """Prepare the collector (databases opened lazily)."""
        self.config = config or Config().load()
        self.logger = logger or Logger("main_hud", str(self.config.get("general.log_level", "INFO")))
        self.oui = OuiLookup()
        self.install = Path(self.config.get("general.install_dir", "/opt/cyberdeck-arsenal"))
        self.data_dir = self.install / "data"
        self.report_dir = Path(self.config.get("scanning.output_dir", self.install / "reports"))
        self._last_packet_bytes: Optional[int] = None
        self._last_packet_time: Optional[float] = None
        self._wifi_cache: List[WifiNetwork] = []
        self._wifi_cache_time = 0.0
        self._connection_owners: Dict[str, str] = {}

    # -- interfaces --------------------------------------------------------- #
    def interfaces(self) -> List[Any]:
        """Return the network interfaces with monitor-mode annotations."""
        return Hardware.interfaces()

    # -- wifi --------------------------------------------------------------- #
    def wifi_networks(self, max_age: float = 30.0) -> Tuple[List[WifiNetwork], Optional[str]]:
        """Survey visible networks; results are cached for *max_age* seconds.

        Prefers ``iw dev <iface> scan`` (needs root); falls back to ``nmcli``.
        """
        if self._wifi_cache and (time.time() - self._wifi_cache_time) < max_age:
            return self._wifi_cache, None

        iface = self._pick_wifi_interface()
        if not iface:
            return [], "no wireless interface detected"

        networks: List[WifiNetwork] = []
        error: Optional[str] = None

        if deps.have("iw"):
            code, out, err = run(["iw", "dev", iface, "scan"], timeout=25, logger=self.logger)
            if code == 0 and out:
                networks = self._parse_iw_scan(out)
            else:
                error = ("iw scan failed (needs root and an unblocked interface)"
                         if os.geteuid() != 0 else (err.strip() or "iw scan returned no data"))

        if not networks and deps.have("nmcli"):
            code, out, _ = run(["nmcli", "-t", "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
                                "dev", "wifi", "list"], timeout=20, logger=self.logger)
            if code == 0 and out:
                networks = self._parse_nmcli(out)
                error = None if networks else error

        self._wifi_cache = networks
        self._wifi_cache_time = time.time()
        return networks, error

    def _pick_wifi_interface(self) -> Optional[str]:
        """Return the configured interface if it is wireless, else any wireless NIC."""
        configured = str(self.config.get("network.monitor_interface", ""))
        wireless = [i.name for i in Hardware.wifi_interfaces()]
        if configured in wireless:
            return configured
        configured = str(self.config.get("network.primary_interface", ""))
        if configured in wireless:
            return configured
        return wireless[0] if wireless else None

    def _parse_iw_scan(self, text: str) -> List[WifiNetwork]:
        """Parse ``iw dev <iface> scan`` output into :class:`WifiNetwork` objects."""
        networks: List[WifiNetwork] = []
        current: Optional[WifiNetwork] = None
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("BSS "):
                if current:
                    networks.append(current)
                bssid = line.split()[1].split("(")[0]
                current = WifiNetwork(bssid=bssid, vendor=self.oui.vendor(bssid))
            elif current is None:
                continue
            elif line.startswith("SSID:"):
                ssid = line[5:].strip()
                current.ssid = ssid or "<hidden>"
            elif line.startswith("signal:"):
                try:
                    current.signal_dbm = int(float(line.split()[1]))
                except (IndexError, ValueError):
                    pass
            elif line.startswith("* channel") or line.startswith("DS Parameter set"):
                match = re.search(r"(\d+)\s*(MHz)?\s*$", line)
                if match:
                    value = int(match.group(1))
                    # "DS Parameter set: channel 6" is the real channel number
                    current.channel = value if value < 200 else current.channel
            elif "RSN:" in line or "WPA:" in line:
                current.encryption = "WPA2/WPA3"
            elif line.startswith("capability:") and "Privacy" not in line:
                current.encryption = "OPEN"
        if current:
            networks.append(current)

        # Convert iw channels expressed as frequencies (2412 -> channel 1)
        for network in networks:
            if network.channel and network.channel > 200:
                network.channel = self._freq_to_channel(network.channel)
        networks.sort(key=lambda n: (n.signal_dbm if n.signal_dbm is not None else -999),
                      reverse=True)
        return networks

    @staticmethod
    def _freq_to_channel(freq: int) -> Optional[int]:
        """Convert a WiFi centre frequency in MHz to a channel number."""
        if 2412 <= freq <= 2484:
            return 14 if freq == 2484 else (freq - 2407) // 5
        if 5000 <= freq <= 5900:
            return (freq - 5000) // 5
        if 5955 <= freq <= 7115:
            return (freq - 5955) // 5 + 1
        return None

    def _parse_nmcli(self, text: str) -> List[WifiNetwork]:
        """Parse ``nmcli -t`` output as a fallback survey source."""
        networks: List[WifiNetwork] = []
        for line in text.splitlines():
            parts = re.split(r"(?<!\\):", line)
            if len(parts) < 5:
                continue
            bssid, ssid, chan, signal, security = parts[0], parts[1], parts[2], parts[3], parts[4]
            try:
                channel = int(chan)
            except ValueError:
                channel = None
            try:
                # nmcli reports quality 0-100; convert to an approximate dBm
                quality = int(signal)
                dbm = int((quality / 2) - 100)
            except ValueError:
                dbm = None
            networks.append(WifiNetwork(
                bssid=bssid, ssid=ssid.replace("\\:", ":") or "<hidden>",
                channel=channel, signal_dbm=dbm,
                encryption=security or "OPEN", vendor=self.oui.vendor(bssid)))
        networks.sort(key=lambda n: (n.signal_dbm if n.signal_dbm is not None else -999),
                      reverse=True)
        return networks

    # -- BLE ---------------------------------------------------------------- #
    def ble_summary(self) -> Tuple[int, List[Dict[str, Any]], Optional[str]]:
        """Return (device count in last 24h, recent devices, error)."""
        path = self.data_dir / "ble.db"
        if not path.exists():
            return 0, [], "no BLE data yet (start ble-scanner.service)"
        try:
            with Database("ble", path=path, logger=self.logger) as db:
                row = db.query_one(
                    "SELECT COUNT(*) AS n FROM ble_devices WHERE last_seen >= datetime('now','-1 day')")
                count = int(row["n"]) if row else 0
                rows = db.query(
                    "SELECT address, name, last_rssi, last_seen, vulnerable, vendor "
                    "FROM ble_devices ORDER BY last_seen DESC LIMIT 8")
                recent = [dict(r) for r in rows]
            return count, recent, None
        except Exception as exc:  # noqa: BLE001 - HUD must never crash
            return 0, [], f"BLE database unreadable: {exc}"

    # -- connections -------------------------------------------------------- #
    def connections(self) -> Tuple[List[Dict[str, str]], int, int]:
        """Return (active connections, established count, listening count)."""
        active: List[Dict[str, str]] = []
        established = 0
        listening = 0
        try:
            if deps.have("ss"):
                code, out, _ = run(["ss", "-tunap"], timeout=8)
                if code == 0:
                    for line in out.splitlines()[1:]:
                        fields = line.split()
                        if len(fields) < 5:
                            continue
                        state = fields[0]
                        if state == "ESTAB":
                            established += 1
                        elif state == "LISTEN":
                            listening += 1
                        if state not in ("ESTAB", "LISTEN"):
                            continue
                        peer = fields[4] if len(fields) > 4 else ""
                        process = ""
                        match = re.search(r'users:\(\("([^"]+)"', line)
                        if match:
                            process = match.group(1)
                        elif "LISTEN" in line:
                            process = "listener"
                        active.append({
                            "state": state,
                            "peer": peer,
                            "process": process,
                            "raw": line,
                        })
            else:
                # Fallback: parse /proc/net/tcp and tcp6 directly
                for proto, proc_file in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
                    try:
                        lines = Path(proc_file).read_text().splitlines()[1:]
                    except OSError:
                        continue
                    for line in lines:
                        fields = line.split()
                        if len(fields) < 4:
                            continue
                        state_hex = fields[3]
                        if state_hex == "01":
                            established += 1
                        elif state_hex == "0A":
                            listening += 1
                        if state_hex not in ("01", "0A"):
                            continue
                        active.append({
                            "state": "ESTAB" if state_hex == "01" else "LISTEN",
                            "peer": self._hex_addr(fields[2]),
                            "process": proto,
                            "raw": line,
                        })
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"connection enumeration failed: {exc}")
        return active, established, listening

    @staticmethod
    def _hex_addr(hex_address: str) -> str:
        """Decode a /proc/net/tcp hex address into ``ip:port``."""
        try:
            address, port = hex_address.split(":")
            port_int = int(port, 16)
            if len(address) == 8:
                octets = [str(int(address[i:i + 2], 16)) for i in (6, 4, 2, 0)]
                return f"{'.'.join(octets)}:{port_int}"
            # IPv6: group 4 bytes at a time
            words = [address[i:i + 8] for i in range(0, len(address), 8)]
            decoded = []
            for word in words:
                decoded.append("".join(f"{int(word[i:i + 2], 16):02x}" for i in (6, 4, 2, 0)))
            return f"[{':'.join(decoded)}]:{port_int}"
        except (ValueError, IndexError):
            return hex_address

    # -- anonymity ---------------------------------------------------------- #
    def anonymity(self) -> Tuple[bool, bool, str]:
        """Return (tor_active, vpn_active, vpn_interface_name)."""
        tor = False
        for pattern in ("tor", "tor-proxy"):
            code, _, _ = run(["pgrep", "-x", pattern], timeout=4)
            if code == 0:
                tor = True
                break
        vpn = False
        name = ""
        code, out, _ = run(["ip", "-o", "link", "show", "type", "wireguard"], timeout=5)
        if code == 0 and out.strip():
            vpn = True
            name = out.split(":")[1].strip() if ":" in out else "wg0"
        else:
            code, _, _ = run(["pgrep", "-x", "openvpn"], timeout=4)
            if code == 0:
                vpn = True
                name = "openvpn"
        return tor, vpn, name

    # -- GPS ---------------------------------------------------------------- #
    def gps(self) -> Optional[Dict[str, Any]]:
        """Read a GPS fix from gpsd (JSON over TCP) or a serial NMEA device."""
        # gpsd is the least invasive source: connect, ask, disconnect.
        try:
            with socket.create_connection(("127.0.0.1", 2947), timeout=1.5) as sock:
                sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
                sock.settimeout(2.0)
                buffer = b""
                deadline = time.time() + 2.0
                while time.time() < deadline:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buffer += chunk
                    for line in buffer.decode(errors="replace").splitlines():
                        if '"lat"' in line and '"lon"' in line:
                            import json
                            data = json.loads(line)
                            return {
                                "lat": round(float(data.get("lat", 0.0)), 6),
                                "lon": round(float(data.get("lon", 0.0)), 6),
                                "speed": data.get("speed", 0.0),
                                "mode": data.get("mode", 0),
                                "source": "gpsd",
                            }
                return None
        except OSError:
            pass

        # Direct serial fallback (NMEA sentences)
        device = self.config.get("gps.device", "")
        if not device or not Path(str(device)).exists() or not deps.have_module("serial"):
            return None
        try:
            import serial  # type: ignore
            with serial.Serial(str(device), int(self.config.get("gps.baud", 9600)),
                               timeout=1.5) as port:
                fix: Dict[str, Any] = {"source": str(device)}
                deadline = time.time() + 2.5
                while time.time() < deadline:
                    line = port.readline().decode(errors="replace").strip()
                    if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                        fields = line.split(",")
                        if len(fields) > 9 and fields[2] and fields[4]:
                            fix["lat"] = self._nmea_deg(fields[2], fields[3])
                            fix["lon"] = self._nmea_deg(fields[4], fields[5])
                            fix["satellites"] = fields[7]
                    if "lat" in fix:
                        return fix
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"serial GPS read failed: {exc}")
        return None

    @staticmethod
    def _nmea_deg(value: str, hemisphere: str) -> float:
        """Convert an NMEA ``ddmm.mmmm`` field into decimal degrees."""
        try:
            degrees = float(value[:2] if hemisphere in ("N", "S") else value[:3])
            minutes = float(value[2:] if hemisphere in ("N", "S") else value[3:])
            result = degrees + minutes / 60.0
            return round(-result if hemisphere in ("S", "W") else result, 6)
        except (ValueError, IndexError):
            return 0.0

    # -- recon summary ------------------------------------------------------ #
    def last_scan(self) -> Optional[Dict[str, Any]]:
        """Summarise the most recent engagement/report directory."""
        if not self.report_dir.is_dir():
            return None
        directories = sorted((d for d in self.report_dir.iterdir() if d.is_dir()),
                             key=lambda d: d.stat().st_mtime, reverse=True)
        if not directories:
            return None
        latest = directories[0]
        files = [f for f in latest.rglob("*") if f.is_file()]
        return {
            "path": str(latest),
            "name": latest.name,
            "age_seconds": time.time() - latest.stat().st_mtime,
            "file_count": len(files),
            "size": sum(f.stat().st_size for f in files),
            "has_report": any(f.suffix in (".md", ".html") for f in files),
        }

    # -- alerts ------------------------------------------------------------- #
    def alerts(self, limit: int = 12) -> List[Dict[str, str]]:
        """Read the most recent alerts from the shared feed."""
        path = self.data_dir / "alerts.db"
        if not path.exists():
            return []
        try:
            with Database("alerts", path=path, logger=self.logger) as db:
                rows = db.query(
                    "SELECT ts, source, severity, title, body FROM alerts "
                    "ORDER BY ts DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]
        except Exception:  # noqa: BLE001
            return []

    # -- services ----------------------------------------------------------- #
    def services(self) -> Dict[str, str]:
        """Return the state of every cyberdeck systemd unit."""
        units = ("cyberdeck-monitor.service", "mac-rotator.timer", "probe-logger.service",
                 "ble-scanner.service", "rogue-ap-detector.service", "usb-watcher.service")
        state: Dict[str, str] = {}
        for unit in units:
            if not deps.have("systemctl"):
                state[unit] = "n/a"
                continue
            code, out, _ = run(["systemctl", "is-active", unit], timeout=5)
            state[unit] = out.strip() if code == 0 and out.strip() else "inactive"
        return state

    # -- packet rate -------------------------------------------------------- #
    def packet_rate(self) -> float:
        """Estimate the current packet rate in packets/second (kernel counters)."""
        total = 0
        try:
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
                fields = line.split(":")
                if len(fields) != 2:
                    continue
                iface = fields[0].strip()
                if iface == "lo":
                    continue
                values = fields[1].split()
                total += int(values[1]) + int(values[2])  # rx packets + tx packets
        except (OSError, ValueError, IndexError):
            return 0.0
        now = time.time()
        rate = 0.0
        if self._last_packet_bytes is not None and self._last_packet_time is not None:
            elapsed = max(now - self._last_packet_time, 0.001)
            rate = max(total - self._last_packet_bytes, 0) / elapsed
        self._last_packet_bytes = total
        self._last_packet_time = now
        return round(rate, 1)

    # -- aggregate ---------------------------------------------------------- #
    def snapshot(self) -> Snapshot:
        """Collect one full snapshot of everything the HUD displays."""
        snap = Snapshot()
        snap.interfaces = self.interfaces()
        snap.wifi, snap.wifi_error = self.wifi_networks()
        snap.ble_count, snap.ble_recent, snap.ble_error = self.ble_summary()
        snap.vitals = Hardware.vitals()
        snap.connections, snap.connection_count, snap.listening_count = self.connections()
        snap.tor_active, snap.vpn_active, snap.vpn_name = self.anonymity()
        if bool(self.config.get("display.show_gps", False)) or bool(self.config.get("gps.enabled", False)):
            snap.gps = self.gps()
        snap.last_scan = self.last_scan()
        snap.alerts = self.alerts()
        snap.services = self.services()
        snap.packet_rate = self.packet_rate()
        snap.uptime_seconds = snap.vitals.get("uptime_seconds")
        return snap


# --------------------------------------------------------------------------- #
# Plain-text rendering (used by --once and as a fallback)
# --------------------------------------------------------------------------- #
def render_plain(snapshot: Snapshot, theme: str = "cyberpunk") -> str:
    """Render a snapshot as colourised plain text for terminals without textual."""
    palette = THEMES.get(theme, THEMES["cyberpunk"])

    def head(title: str) -> str:
        return colour(f"── {title} " + "─" * max(0, 66 - len(title)), palette["primary"])

    lines: List[str] = []
    lines.append(colour(f"  CYBERDECK HUD  ::  {snapshot.ts}", palette["accent"]))

    # Interfaces
    lines.append(head("INTERFACES"))
    if not snapshot.interfaces:
        lines.append("  no network interfaces detected")
    for iface in snapshot.interfaces:
        if iface.kind == "loopback":
            continue
        marker = "●" if iface.state == "up" else "○"
        monitor = " [MONITOR]" if iface.monitor_capable else ""
        lines.append(f"  {marker} {iface.name:<12} {iface.kind:<8} {iface.mac:<18} "
                     f"{str(iface.driver):<14}{monitor}")

    # WiFi
    lines.append(head("WIFI"))
    if snapshot.wifi:
        strongest = snapshot.wifi[0]
        channels = sorted({n.channel for n in snapshot.wifi if n.channel})
        open_count = sum(1 for n in snapshot.wifi if n.encryption.upper() == "OPEN")
        lines.append(f"  {len(snapshot.wifi)} networks visible   strongest: {strongest.ssid} "
                     f"({strongest.signal_dbm} dBm)   channels: {channels}")
        if open_count:
            lines.append(colour(f"  ! {open_count} open network(s) in range", palette["warning"]))
        for network in snapshot.wifi[:8]:
            enc = network.encryption.split("/")[0][:6]
            lines.append(f"    {network.signal_dbm if network.signal_dbm is not None else '?':>5} dBm  "
                         f"ch{str(network.channel or '?'):<3} {enc:<7} {network.ssid[:28]:<28} "
                         f"{network.bssid}")
    else:
        lines.append(f"  {snapshot.wifi_error or 'no networks found'}")

    # Vitals
    vitals = snapshot.vitals
    lines.append(head("VITALS"))
    cpu = vitals.get("cpu_percent")
    ram = vitals.get("ram_percent")
    temp = vitals.get("temperature")
    battery = vitals.get("battery")
    lines.append(f"  cpu {f'{cpu:.0f}%' if cpu is not None else 'n/a':<6} "
                 f"ram {f'{ram:.0f}%' if ram is not None else 'n/a':<6} "
                 f"temp {f'{temp:.0f}C' if temp is not None else 'n/a':<7} "
                 f"disk {vitals.get('disk_percent', 'n/a')}%  "
                 f"battery {str(battery['percent']) + '%' if battery else 'n/a'}")
    lines.append(f"  uptime {human_duration(snapshot.uptime_seconds)}   "
                 f"load {vitals.get('load_avg')}   packets/s {snapshot.packet_rate}")

    # Posture
    lines.append(head("POSTURE"))
    lines.append(f"  tor {'ACTIVE' if snapshot.tor_active else 'off':<8} "
                 f"vpn {snapshot.vpn_name if snapshot.vpn_active else 'off':<10} "
                 f"connections {snapshot.connection_count} established, "
                 f"{snapshot.listening_count} listening")
    if snapshot.gps and "lat" in snapshot.gps:
        lines.append(f"  gps {snapshot.gps['lat']}, {snapshot.gps['lon']} "
                     f"(source: {snapshot.gps.get('source')})")
    lines.append(f"  BLE devices (24h): {snapshot.ble_count}"
                 + (f"  [{snapshot.ble_error}]" if snapshot.ble_error else ""))
    for device in snapshot.ble_recent[:3]:
        flag = colour(" VULN", palette["error"]) if device.get("vulnerable") else ""
        lines.append(f"    {device.get('address', '?'):<18} "
                     f"{str(device.get('name') or 'unknown')[:24]:<24} "
                     f"{device.get('last_rssi', '?')} dBm{flag}")
    if snapshot.last_scan:
        lines.append(f"  last recon: {snapshot.last_scan['name']} "
                     f"({human_duration(snapshot.last_scan['age_seconds'])} ago, "
                     f"{snapshot.last_scan['file_count']} files)")

    # Alerts
    lines.append(head("ALERT FEED"))
    if snapshot.alerts:
        for alert in snapshot.alerts[:10]:
            colour_code = palette["error"] if alert["severity"] in ("ERROR", "CRITICAL") \
                else palette["warning"] if alert["severity"] in ("WARNING", "ALERT") \
                else palette["dim"]
            stamp = alert["ts"][11:19] if len(alert["ts"]) > 19 else alert["ts"]
            lines.append(f"  {stamp} {colour(alert['severity'][:7], colour_code):<16} "
                         f"{alert['title'][:52]}")
    else:
        lines.append(colour("  feed empty - alerts appear here as they fire", palette["dim"]))

    # Services
    lines.append(head("SERVICES"))
    for unit, state in snapshot.services.items():
        marker = "✔" if state == "active" else "·"
        lines.append(f"  {marker} {unit:<30} {state}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Textual application
# --------------------------------------------------------------------------- #
def build_textual_app(collector: Collector, theme: str, refresh: float, compact: bool,
                      logger: Logger) -> Any:
    """Construct and return the Textual App class (imported lazily)."""
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.widgets import DataTable, Footer, Header, Sparkline, Static

    palette = THEMES.get(theme, THEMES["cyberpunk"])

    class CyberdeckHUD(App):
        """The cyberdeck operations HUD."""

        TITLE = "CYBERDECK ARSENAL"
        SUB_TITLE = "operations dashboard"
        CSS = f"""
        Screen {{
            background: {palette['panel']};
            color: {palette['accent']};
        }}
        #top-row, #mid-row, #bottom-row {{
            height: 1fr;
        }}
        .panel {{
            border: round {palette['dim']};
            padding: 0 1;
            height: 1fr;
        }}
        .panel > .panel-title {{
            color: {palette['primary']};
            text-style: bold;
        }}
        DataTable {{
            height: 1fr;
            background: {palette['panel']};
        }}
        DataTable > .datatable--header {{
            background: {palette['panel']};
            color: {palette['secondary']};
            text-style: bold;
        }}
        DataTable > .datatable--cursor {{
            background: {palette['dim']};
            color: {palette['primary']};
        }}
        #alert-feed {{
            height: 1fr;
        }}
        Sparkline {{
            height: 3;
        }}
        Header {{
            background: {palette['panel']};
            color: {palette['primary']};
        }}
        Footer {{
            background: {palette['panel']};
            color: {palette['dim']};
        }}
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "force_refresh", "Refresh"),
            ("s", "drill_scan", "Scan"),
            ("p", "drill_packets", "Packets"),
            ("t", "drill_threats", "Threats"),
            ("w", "drill_wifi", "WiFi"),
            ("n", "drill_netmap", "Netmap"),
            ("v", "drill_vault", "Vault"),
            ("d", "drill_status", "Status"),
            ("+", "faster", "Faster"),
            ("-", "slower", "Slower"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self.collector = collector
            self.refresh_interval = refresh
            self.packet_history: List[float] = []
            self.snapshot: Optional[Snapshot] = None
            self.hostname = socket.gethostname()

        # -- layout --------------------------------------------------------- #
        def compose(self) -> ComposeResult:
            """Build the dashboard layout."""
            yield Header(show_clock=True)
            with VerticalScroll():
                with Horizontal(id="top-row"):
                    yield Static(id="interfaces", classes="panel")
                    yield Static(id="wifi", classes="panel")
                with Horizontal(id="mid-row"):
                    yield Static(id="ble", classes="panel")
                    yield Static(id="vitals", classes="panel")
                    yield Static(id="posture", classes="panel")
                with Horizontal(id="bottom-row"):
                    yield Static(id="recon", classes="panel")
                    yield Static(id="alerts", classes="panel")
            yield Footer()

        def on_mount(self) -> None:
            """Start the refresh loop."""
            logger.info("HUD started (theme=%s, refresh=%ss, compact=%s)", theme, refresh, compact)
            self.set_interval(self.refresh_interval, self.tick)
            self.tick()

        # -- periodic update ------------------------------------------------ #
        def tick(self) -> None:
            """Gather a snapshot and repaint every panel."""
            try:
                snapshot = self.collector.snapshot()
            except Exception as exc:  # noqa: BLE001 - never kill the HUD
                logger.error(f"snapshot failed: {exc}")
                return
            self.snapshot = snapshot
            self.packet_history.append(snapshot.packet_rate)
            self.packet_history = self.packet_history[-60:]
            self.paint(snapshot)

        def paint(self, snap: Snapshot) -> None:
            """Render each panel from *snap*."""
            self._paint_interfaces(snap)
            self._paint_wifi(snap)
            self._paint_ble(snap)
            self._paint_vitals(snap)
            self._paint_posture(snap)
            self._paint_recon(snap)
            self._paint_alerts(snap)

        # -- panels --------------------------------------------------------- #
        def _paint_interfaces(self, snap: Snapshot) -> None:
            lines = [f"[b {palette['primary']}]▍INTERFACES[/]"]
            if not snap.interfaces:
                lines.append("[dim]no interfaces detected[/]")
            for iface in snap.interfaces:
                if iface.kind == "loopback":
                    continue
                state_colour = palette["ok"] if iface.state == "up" else palette["dim"]
                monitor = f" [{palette['secondary']}]MON[/]" if iface.monitor_capable else ""
                lines.append(
                    f"[{state_colour}]●[/] {iface.name:<11} "
                    f"[dim]{iface.kind:<8}[/] {iface.mac}"
                    f"  [dim]{iface.driver}[/]{monitor}")
            self.query_one("#interfaces", Static).update("\n".join(lines))

        def _paint_wifi(self, snap: Snapshot) -> None:
            lines = [f"[b {palette['primary']}]▍WIFI[/]"]
            if not snap.wifi:
                lines.append(f"[dim]{snap.wifi_error or 'no networks found'}[/]")
            else:
                strongest = snap.wifi[0]
                open_count = sum(1 for n in snap.wifi if n.encryption.upper() == "OPEN")
                lines.append(f"{len(snap.wifi)} APs · strongest "
                             f"[b]{strongest.ssid[:18]}[/] {strongest.signal_dbm} dBm")
                if open_count:
                    lines.append(f"[{palette['warning']}]! {open_count} open network(s)[/]")
                for network in snap.wifi[:8]:
                    bar_len = 0
                    if network.signal_dbm is not None:
                        bar_len = max(1, min(5, int((network.signal_dbm + 100) / 12)))
                    bar = f"[{palette['ok']}]{'▮' * bar_len}[/]"
                    lines.append(f"{bar} [dim]ch{str(network.channel or '?'):<3}[/]"
                                 f"{network.ssid[:20]:<20} [dim]{network.bssid}[/]")
            self.query_one("#wifi", Static).update("\n".join(lines))

        def _paint_ble(self, snap: Snapshot) -> None:
            lines = [f"[b {palette['primary']}]▍BLE[/]"]
            if snap.ble_error:
                lines.append(f"[dim]{snap.ble_error}[/]")
            lines.append(f"[b]{snap.ble_count}[/] device(s) seen in 24h")
            for device in snap.ble_recent[:6]:
                flag = f" [{palette['error']}]VULN[/]" if device.get("vulnerable") else ""
                lines.append(f"[dim]{device.get('address', '?')[:17]}[/] "
                             f"{str(device.get('name') or 'unknown')[:14]:<14} "
                             f"{device.get('last_rssi', '?')}dBm{flag}")
            self.query_one("#ble", Static).update("\n".join(lines))

        def _paint_vitals(self, snap: Snapshot) -> None:
            vitals = snap.vitals
            lines = [f"[b {palette['primary']}]▍VITALS[/]"]

            def gauge(label: str, value: Optional[float], warn: float = 75, crit: float = 90) -> str:
                if value is None:
                    return f"{label:<4} [dim]n/a[/]"
                colour_code = palette["ok"]
                if value >= crit:
                    colour_code = palette["error"]
                elif value >= warn:
                    colour_code = palette["warning"]
                filled = int(max(0, min(10, value / 10)))
                bar = "█" * filled + "░" * (10 - filled)
                return f"{label:<4} [{colour_code}]{bar}[/] [{colour_code}]{value:>5.1f}%[/]"

            lines.append(gauge("CPU", vitals.get("cpu_percent")))
            lines.append(gauge("RAM", vitals.get("ram_percent")))
            lines.append(gauge("DISK", vitals.get("disk_percent"), 80, 92))
            temp = vitals.get("temperature")
            temp_colour = palette["ok"]
            if temp is not None:
                temp_colour = palette["error"] if temp > 80 else palette["warning"] if temp > 65 else palette["ok"]
            lines.append(f"TEMP [{temp_colour}]{f'{temp:.0f}°C' if temp is not None else 'n/a':>5}[/]"
                         f"  [{palette['accent']}]pkts/s {snap.packet_rate:.0f}[/]")
            battery = vitals.get("battery")
            if battery:
                pct = battery["percent"]
                battery_colour = palette["error"] if pct < 20 else palette["warning"] if pct < 40 else palette["ok"]
                lines.append(f"BATT [{battery_colour}]{pct:>4}%[/] [dim]{battery['status']}[/]")
            lines.append(f"[dim]up {human_duration(snap.uptime_seconds)}  "
                         f"load {vitals.get('load_avg', ('n/a',))[0] if vitals.get('load_avg') else 'n/a'}[/]")
            self.query_one("#vitals", Static).update("\n".join(lines))

        def _paint_posture(self, snap: Snapshot) -> None:
            lines = [f"[b {palette['primary']}]▍POSTURE[/]"]
            tor = f"[{palette['ok']}]ACTIVE[/]" if snap.tor_active else "[dim]off[/]"
            vpn = f"[{palette['ok']}]{snap.vpn_name}[/]" if snap.vpn_active else "[dim]off[/]"
            lines.append(f"tor {tor}   vpn {vpn}")
            lines.append(f"conns [b]{snap.connection_count}[/] est · "
                         f"[b]{snap.listening_count}[/] listeners")
            for connection in snap.connections[:5]:
                peer = connection["peer"]
                if len(peer) > 34:
                    peer = peer[:31] + "..."
                lines.append(f"[dim]{connection['state']:<5}[/] {peer}")
            if snap.gps and "lat" in snap.gps:
                lines.append(f"[{palette['secondary']}]gps {snap.gps['lat']}, {snap.gps['lon']}[/]")
            self.query_one("#posture", Static).update("\n".join(lines))

        def _paint_recon(self, snap: Snapshot) -> None:
            lines = [f"[b {palette['primary']}]▍RECON[/]"]
            if snap.last_scan:
                scan = snap.last_scan
                lines.append(f"last: [b]{scan['name'][:28]}[/]")
                lines.append(f"[dim]{human_duration(scan['age_seconds'])} ago · "
                             f"{scan['file_count']} files · {human_bytes(scan['size'])}[/]")
                if scan["has_report"]:
                    lines.append(f"[{palette['ok']}]report available[/]")
            else:
                lines.append("[dim]no engagement output yet[/]")
                lines.append("[dim]run: cdeck profile <target>[/]")
            lines.append("")
            lines.append(f"[b {palette['primary']}]▍SERVICES[/]")
            for unit, state in snap.services.items():
                colour_code = palette["ok"] if state == "active" else palette["dim"]
                lines.append(f"[{colour_code}]·[/] {unit.replace('.service', '').replace('.timer', '')}"
                             f" [dim]{state}[/]")
            self.query_one("#recon", Static).update("\n".join(lines))

        def _paint_alerts(self, snap: Snapshot) -> None:
            lines = [f"[b {palette['primary']}]▍ALERT FEED[/]"]
            if not snap.alerts:
                lines.append("[dim]feed empty[/]")
                lines.append("[dim]alerts from every module land here[/]")
            severity_colour = {
                "CRITICAL": palette["error"], "ERROR": palette["error"],
                "ALERT": palette["warning"], "WARNING": palette["warning"],
                "INFO": palette["dim"],
            }
            for alert in snap.alerts[:14]:
                colour_code = severity_colour.get(alert["severity"], palette["accent"])
                stamp = alert["ts"][11:19] if len(alert["ts"]) > 19 else alert["ts"]
                body = f" [dim]{alert['body'][:28]}[/]" if alert.get("body") else ""
                lines.append(f"[dim]{stamp}[/] [{colour_code}]{alert['severity'][:7]:<7}[/] "
                             f"{alert['title'][:30]}{body}")
            self.query_one("#alerts", Static).update("\n".join(lines))

        # -- actions -------------------------------------------------------- #
        def action_force_refresh(self) -> None:
            """Force an immediate repaint."""
            collector._wifi_cache_time = 0.0  # noqa: SLF001 - intentional cache bust
            self.tick()
            self.notify("refreshed")

        def _spawn(self, command: str, description: str) -> None:
            """Suspend the TUI and run a cdeck subcommand."""
            self.notify(f"opening {description}...")
            with self.suspend():
                os.system(f"cdeck {command} || read -r -p 'press enter to return'")  # noqa: S605

        def action_drill_scan(self) -> None:
            """Open the network scanner for the local subnet."""
            iface = collector._pick_wifi_interface()  # noqa: SLF001
            subnet = "192.168.1.0/24"
            if iface:
                code, out, _ = run(["ip", "-4", "addr", "show", iface], timeout=5)
                match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+", out or "")
                if match:
                    subnet = f"{match.group(1)}.0/24"
            self._spawn(f"scan {subnet}", f"scan of {subnet}")

        def action_drill_packets(self) -> None:
            self._spawn("packets", "packet weather")

        def action_drill_threats(self) -> None:
            self._spawn("threats", "threat ticker")

        def action_drill_wifi(self) -> None:
            self._spawn("wifi", "WiFi arsenal")

        def action_drill_netmap(self) -> None:
            self._spawn("netmap", "network map")

        def action_drill_vault(self) -> None:
            self._spawn("vault list", "encrypted vault")

        def action_drill_status(self) -> None:
            self._spawn("status", "status summary")

        def action_faster(self) -> None:
            """Halve the refresh interval (minimum 0.5s)."""
            self.refresh_interval = max(0.5, self.refresh_interval / 2)
            self.set_interval(self.refresh_interval, self.tick)
            self.notify(f"refresh interval {self.refresh_interval:.1f}s")

        def action_slower(self) -> None:
            """Double the refresh interval (maximum 30s)."""
            self.refresh_interval = min(30.0, self.refresh_interval * 2)
            self.set_interval(self.refresh_interval, self.tick)
            self.notify(f"refresh interval {self.refresh_interval:.1f}s")

    return CyberdeckHUD


# --------------------------------------------------------------------------- #
# Rich fallback loop
# --------------------------------------------------------------------------- #
def run_rich_fallback(collector: Collector, theme: str, refresh: float) -> int:
    """Live-updating rich view used when textual is unavailable."""
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel

    console = Console()
    palette = THEMES.get(theme, THEMES["cyberpunk"])
    with Live(console=console, refresh_per_second=max(1, int(1 / refresh)), screen=True) as live:
        while True:
            try:
                snapshot = collector.snapshot()
                live.update(Panel(render_plain(snapshot, theme),
                                  title=f"[{palette['primary']}]CYBERDECK HUD[/]",
                                  border_style=palette["dim"]))
                time.sleep(refresh)
            except KeyboardInterrupt:
                break
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="main_hud.py",
        description="cyberdeck-arsenal main HUD dashboard",
        epilog="Also available as: cdeck dashboard")
    parser.add_argument("--refresh", type=float, default=None,
                        help="refresh interval in seconds (default: from cyberdeck.conf)")
    parser.add_argument("--theme", choices=sorted(THEMES), default=None,
                        help="colour theme (default: from cyberdeck.conf)")
    parser.add_argument("--compact", action="store_true",
                        help="compact layout for small screens")
    parser.add_argument("--once", action="store_true",
                        help="print a single snapshot and exit (no TUI)")
    parser.add_argument("--json", action="store_true",
                        help="with --once, emit machine-readable JSON")
    parser.add_argument("--no-legal-check", action="store_true",
                        help="skip the legal acknowledgement prompt (passive tool)")
    parser.add_argument("--version", action="version", version=f"main_hud {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("main_hud", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)))
    theme = args.theme or str(config.get("display.theme", "cyberpunk"))
    refresh = args.refresh or float(config.get("display.hud_refresh_rate", 2))
    compact = args.compact or bool(config.get("display.compact", False))

    collector = Collector(config, logger)

    if args.once:
        snapshot = collector.snapshot()
        if args.json:
            import json
            payload = {
                "ts": snapshot.ts,
                "interfaces": [i.as_dict() for i in snapshot.interfaces],
                "wifi": [vars(n) for n in snapshot.wifi],
                "ble_count": snapshot.ble_count,
                "vitals": snapshot.vitals,
                "connections": snapshot.connection_count,
                "listeners": snapshot.listening_count,
                "tor": snapshot.tor_active,
                "vpn": snapshot.vpn_name if snapshot.vpn_active else None,
                "gps": snapshot.gps,
                "last_scan": snapshot.last_scan,
                "alerts": snapshot.alerts,
                "services": snapshot.services,
                "packet_rate": snapshot.packet_rate,
            }
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(render_plain(snapshot, theme))
        return 0

    try:
        from textual.app import App  # noqa: F401
        textual_available = True
    except ImportError:
        textual_available = False

    if not textual_available:
        logger.warn("textual is not installed - using the rich fallback view")
        logger.info("install it with: /opt/cyberdeck-arsenal/venv/bin/pip install textual rich")
        try:
            import rich  # noqa: F401
            return run_rich_fallback(collector, theme, refresh)
        except ImportError:
            logger.warn("rich is not installed either - printing a static snapshot")
            print(render_plain(collector.snapshot(), theme))
            return 0

    app_class = build_textual_app(collector, theme, refresh, compact, logger)
    try:
        app_class().run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # noqa: BLE001 - last-resort fallback
        logger.error(f"HUD crashed: {exc}")
        logger.info("falling back to the static snapshot")
        print(render_plain(collector.snapshot(), theme))
        return 1
    logger.info("HUD closed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
