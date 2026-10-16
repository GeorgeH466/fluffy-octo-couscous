#!/usr/bin/env python3
"""
service_watcher.py - passive LAN service discovery (mDNS / SSDP / LLMNR)
=======================================================================

Description
-----------
Listens for the three protocols that every consumer network leaks constantly
and records what is being advertised:

    * mDNS  (UDP 5353) - Apple/Bonjour/Avahi: printers, Apple TVs, NAS, Chromecasts
    * SSDP  (UDP 1900) - UPnP: routers, smart TVs, IoT hubs, cameras
    * LLMNR (UDP 5355) - Windows name resolution: workstations and shares
    * NBNS  (UDP 137)  - legacy NetBIOS name service (optional)

Everything is stored in ``data/services.db`` with the host, port, advertised
service type and the raw detail string. This gives an operator a passive asset
inventory without sending a single probe packet.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; scapy (packet capture) + root for passive sniffing;
              falls back to a socket-based multicast listener
Licence     : MIT - passive monitoring of networks you are authorised to observe

Usage
-----
    sudo cdeck services --duration 60
    sudo python3 recon/passive/service_watcher.py --continuous --from-service
    python3 recon/passive/service_watcher.py --list
    python3 recon/passive/service_watcher.py --json --duration 30
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import sqlite3
import struct
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
        C, Config, Database, Hardware, Logger, colour, deps, now_iso, run,
    )
except ImportError as exc:
    print(f"service_watcher: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

MDNS_GROUP = "224.0.0.251"
SSDP_GROUP = "239.255.255.250"
LLMNR_GROUP = "224.0.0.252"

#: Friendly names for the mDNS service types that matter on a deck
MDNS_SERVICE_NAMES: Dict[str, str] = {
    "_http._tcp.local": "HTTP", "_https._tcp.local": "HTTPS",
    "_ssh._tcp.local": "SSH", "_sftp-ssh._tcp.local": "SFTP",
    "_smb._tcp.local": "SMB/CIFS", "_afpovertcp._tcp.local": "AFP (Apple file sharing)",
    "_ipp._tcp.local": "Printer (IPP)", "_ipps._tcp.local": "Printer (IPPS)",
    "_printer._tcp.local": "Printer (LPD)", "_pdl-datastream._tcp.local": "Printer (raw)",
    "_raop._tcp.local": "AirPlay audio", "_airplay._tcp.local": "AirPlay",
    "_googlecast._tcp.local": "Chromecast", "_spotify-connect._tcp.local": "Spotify Connect",
    "_workstation._tcp.local": "Workstation", "_device-info._tcp.local": "Device info",
    "_rfb._tcp.local": "VNC", "_rdp._tcp.local": "RDP", "_companion-link._tcp.local": "Apple companion",
    "_homekit._tcp.local": "HomeKit", "_hap._tcp.local": "HomeKit accessory",
    "_nvstream._tcp.local": "NVIDIA GameStream", "_services._dns-sd._udp.local": "Service browser",
    "_adb._tcp.local": "Android ADB (wireless debugging)",
    "_esphomelib._tcp.local": "ESPHome (IoT)", "_sonos._tcp.local": "Sonos",
    "_matter._tcp.local": "Matter (smart home)",
}

#: UPnP device types worth flagging
SSDP_INTERESTING = ("internetgatewaydevice", "wanconnectiondevice", "wanipconnection",
                    "mediaserver", "medianetworkdevice", "printer", "camera",
                    "basicdevice", "wanpppconnection")


@dataclass
class ServiceEntry:
    """An advertised service on the local network."""

    protocol: str
    host: str
    service: str
    port: Optional[int] = None
    detail: str = ""
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    sightings: int = 1

    def as_dict(self) -> Dict[str, Any]:
        """Serialise the entry."""
        return {
            "protocol": self.protocol, "host": self.host, "port": self.port,
            "service": self.service, "detail": self.detail,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "sightings": self.sightings,
        }

    @property
    def key(self) -> str:
        """De-duplication key."""
        return f"{self.protocol}:{self.host}:{self.port}:{self.service}".lower()


class ServiceWatcher:
    """Sniffs mDNS/SSDP/LLMNR and stores the advertised services."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None) -> None:
        """Open the services database."""
        self.config = config or Config().load()
        self.logger = logger or Logger("service_watcher",
                                       str(self.config.get("general.log_level", "INFO")))
        self.db = Database("services", logger=self.logger)
        self.entries: Dict[str, ServiceEntry] = {}
        self.lock = threading.Lock()
        self.running = False
        self.packet_count = 0
        self.interface: Optional[str] = self._pick_interface()
        self.warnings: List[str] = []

    def _pick_interface(self) -> Optional[str]:
        """Use the configured primary interface, or the default route's device."""
        code, out, _ = run(["ip", "route", "show", "default"], timeout=5)
        if code == 0 and out and "dev" in out.split():
            return out.split()[out.split().index("dev") + 1]
        configured = str(self.config.get("network.primary_interface", "") or "")
        return configured or None

    # -- capture ------------------------------------------------------------ #
    def sniff(self, duration: Optional[float]) -> bool:
        """Sniff discovery protocols with scapy."""
        if os.geteuid() != 0:
            self.warnings.append("passive sniffing needs root")
            return False
        try:
            from scapy.all import DNS, IP, UDP, IPv6, sniff as scapy_sniff  # type: ignore
        except ImportError:
            self.warnings.append("scapy is not installed")
            return False

        filter_expression = "udp port 5353 or udp port 1900 or udp port 5355 or udp port 137"
        self.logger.info(f"listening for mDNS/SSDP/LLMNR on {self.interface or 'any'}"
                         + (f" for {duration:.0f}s" if duration else ""))
        self.running = True

        def handler(packet: Any) -> None:
            try:
                self.packet_count += 1
                if packet.haslayer(IP):
                    source = packet[IP].src
                elif packet.haslayer(IPv6):
                    source = packet[IPv6].src
                else:
                    return
                if not packet.haslayer(UDP):
                    return
                udp = packet[UDP]
                payload = bytes(udp.payload)
                if udp.dport == 5353 or udp.sport == 5353:
                    self._handle_mdns(source, packet)
                elif udp.dport == 1900 or udp.sport == 1900:
                    self._handle_ssdp(source, payload)
                elif udp.dport == 5355 or udp.sport == 5355:
                    self._handle_llmnr(source, payload)
                elif udp.dport == 137 or udp.sport == 137:
                    self._handle_nbns(source, payload)
            except Exception as exc:  # noqa: BLE001 - the sniffer must survive
                self.logger.debug(f"service parse error: {exc}")

        try:
            scapy_sniff(iface=self.interface, filter=filter_expression, prn=handler,
                        store=False, timeout=duration,
                        stop_filter=lambda _p: not self.running)
        except KeyboardInterrupt:
            self.logger.info("service sniffing interrupted")
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"sniffing failed: {exc}")
            self.logger.debug(f"sniffing failed: {exc}")
            return False
        finally:
            self.running = False
        return True

    def _handle_mdns(self, source: str, packet: Any) -> None:
        """Extract service announcements from an mDNS packet."""
        from scapy.all import DNS, DNSRR  # type: ignore

        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        records: List[Any] = []
        for layer in (getattr(dns, "an", None), getattr(dns, "ns", None),
                      getattr(dns, "ar", None)):
            record = layer
            while record is not None and hasattr(record, "rrname"):
                records.append(record)
                record = record.payload if hasattr(record, "payload") else None
                if record is not None and not hasattr(record, "rrname"):
                    break
        for record in records[:40]:
            try:
                name = record.rrname.decode(errors="replace").rstrip(".")
                rtype = int(getattr(record, "type", 0))
                services: List[Tuple[str, Optional[int]]] = []
                if rtype in (12, 33):  # PTR / SRV
                    for service_type, friendly in MDNS_SERVICE_NAMES.items():
                        if service_type.rstrip(".").lower() in name.lower():
                            port = None
                            if rtype == 33 and hasattr(record, "port"):
                                port = int(record.port)
                            services.append((friendly, port))
                    if not services and "_tcp" in name or "_udp" in name:
                        services.append((name, None))
                elif rtype == 16:  # TXT
                    detail = str(getattr(record, "rdata", ""))[:200]
                    self.record("mDNS", source, name, None, detail)
                    continue
                for friendly, port in services:
                    if port is None:
                        port = self._guess_port(friendly)
                    self.record("mDNS", source, friendly, port, f"{name}")
            except Exception as exc:  # noqa: BLE001
                self.logger.debug(f"mDNS record parse failed: {exc}")

    @staticmethod
    def _guess_port(service: str) -> Optional[int]:
        """Map a friendly service name onto its usual port."""
        mapping = {"HTTP": 80, "HTTPS": 443, "SSH": 22, "SFTP": 22, "SMB/CIFS": 445,
                   "AFP (Apple file sharing)": 548, "Printer (IPP)": 631,
                   "Printer (IPPS)": 631, "Printer (LPD)": 515, "AirPlay": 7000,
                   "AirPlay audio": 5000, "Chromecast": 8009, "VNC": 5900, "RDP": 3389,
                   "Spotify Connect": 4070, "Android ADB (wireless debugging)": 5555}
        return mapping.get(service)

    def _handle_ssdp(self, source: str, payload: bytes) -> None:
        """Extract UPnP device descriptions from SSDP traffic."""
        text = payload.decode(errors="replace")
        header = text.split("\r\n\r\n")[0]
        if not header:
            return
        first_line = header.splitlines()[0] if header.splitlines() else ""
        info: Dict[str, str] = {}
        for line in header.splitlines()[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                info[key.strip().lower()] = value.strip()
        location = info.get("location", "")
        server = info.get("server", "")
        usn = info.get("usn", "")
        device_type = info.get("nt", "") or info.get("st", "")
        interesting = any(token in device_type.lower() for token in SSDP_INTERESTING)
        service = device_type.split(":")[-2] if device_type.count(":") >= 3 else "UPnP device"
        detail = "; ".join(part for part in (
            f"server={server}" if server else "",
            f"location={location}" if location else "",
            f"usn={usn}" if usn else "",
            f"first-line={first_line}" if first_line else "") if part)
        if first_line.startswith("NOTIFY"):
            detail = "announcement " + detail
        severity_note = " [internet-gateway]" if interesting else ""
        self.record("SSDP", source, service + severity_note, self._port_from_location(location),
                    detail)
        if interesting:
            try:
                self.db.event("service_watcher", "service",
                              f"UPnP gateway/media device advertised by {source}: {device_type}",
                              "INFO", {"host": source, "type": device_type, "location": location})
            except sqlite3.Error:
                pass

    @staticmethod
    def _port_from_location(location: str) -> Optional[int]:
        """Extract the port from an SSDP LOCATION URL."""
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(location)
            return parsed.port or (80 if parsed.scheme == "http" else 443)
        except ValueError:
            return None

    def _handle_llmnr(self, source: str, payload: bytes) -> None:
        """Extract names from LLMNR queries and responses."""
        try:
            from scapy.all import DNS  # type: ignore
            from scapy.layers.dns import dnsqtypes  # type: ignore
        except ImportError:
            return
        if len(payload) < 12:
            return
        try:
            name = self._decode_dns_name(payload[12:])
        except Exception:  # noqa: BLE001
            return
        if name:
            self.record("LLMNR", source, "name-resolution", None, f"queried/announced: {name}")

    def _handle_nbns(self, source: str, payload: bytes) -> None:
        """Extract NetBIOS names (legacy Windows/Samba)."""
        try:
            # NBNS header is 12 bytes; the name field is 32 bytes of half-ASCII
            if len(payload) < 44:
                return
            encoded = payload[12:44]
            name = bytes((encoded[i] - 0x41) << 4 | (encoded[i + 1] - 0x41)
                         for i in range(0, 32, 2)).decode(errors="replace").strip()
            if name and name[0].isprintable():
                self.record("NBNS", source, "netbios-name", 137, f"name={name}")
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"NBNS parse failed: {exc}")

    @staticmethod
    def _decode_dns_name(data: bytes) -> str:
        """Decode a DNS label sequence into a dotted name (no compression support)."""
        labels: List[str] = []
        index = 0
        while index < len(data):
            length = data[index]
            if length == 0:
                break
            if length > 63:  # compression pointer
                break
            label = data[index + 1:index + 1 + length].decode(errors="replace")
            labels.append(label)
            index += length + 1
        return ".".join(labels)

    # -- multicast listener fallback --------------------------------------- #
    def run_multicast_listener(self, duration: Optional[float], groups: Sequence[str] = (
            MDNS_GROUP, SSDP_GROUP, LLMNR_GROUP)) -> None:
        """Fallback: join multicast groups with raw sockets and listen.

        This misses unicast responses but needs no root beyond joining the group.
        """
        sockets: List[socket.socket] = []
        for group in groups:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", 5353 if group == MDNS_GROUP else 1900 if group == SSDP_GROUP else 5355))
                membership = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton("0.0.0.0"))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
                sock.settimeout(1.0)
                sockets.append(sock)
                self.logger.debug(f"joined multicast group {group}")
            except OSError as exc:
                self.warnings.append(f"could not join {group}: {exc}")
        if not sockets:
            self.logger.error("could not join any multicast group - run with root or use scapy")
            return

        self.logger.info(f"listening on {len(sockets)} multicast group(s)")
        deadline = time.time() + duration if duration else None
        while self.running and (not deadline or time.time() < deadline):
            for sock in sockets:
                try:
                    data, address = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                source = address[0]
                if b"_" in data and b"local" in data:
                    text = data.decode(errors="replace")
                    found = re.findall(r"(_[a-z0-9-]+\._(?:tcp|udp)\.local)", text)
                    for service_type in set(found):
                        friendly = next((name for key, name in MDNS_SERVICE_NAMES.items()
                                         if key.rstrip(".") in service_type.rstrip(".")),
                                        service_type)
                        self.record("mDNS", source, friendly,
                                    self._guess_port(friendly), service_type)
                elif b"HTTP/1.1" in data or b"NOTIFY" in data or b"M-SEARCH" in data:
                    self._handle_ssdp(source, data)
                else:
                    self.record("multicast", source, "unknown", None,
                                data[:120].decode(errors="replace").replace("\r", " "))
        for sock in sockets:
            sock.close()

    # -- storage ------------------------------------------------------------ #
    def record(self, protocol: str, host: str, service: str, port: Optional[int],
               detail: str = "") -> None:
        """Store a service sighting, de-duplicated."""
        entry = ServiceEntry(protocol=protocol, host=host, service=service[:80],
                             port=port, detail=detail[:400])
        with self.lock:
            existing = self.entries.get(entry.key)
            if existing:
                existing.last_seen = entry.last_seen
                existing.sightings += 1
                entry = existing
            else:
                self.entries[entry.key] = entry
                self.logger.info(f"{protocol}: {host} "
                                 f"{service} {f'port {port} ' if port else ''}"
                                 f"{detail[:60]}")
                try:
                    self.db.event("service_watcher", "service",
                                  f"{protocol} service advertised: {service} on {host}",
                                  "INFO", entry.as_dict())
                except sqlite3.Error:
                    pass
        try:
            self.db.execute(
                "INSERT INTO services (ts, protocol, host, port, service, detail) "
                "VALUES (?,?,?,?,?,?)",
                (now_iso(), protocol, host, port, service[:80], detail[:400]))
        except sqlite3.Error as exc:
            self.logger.debug(f"could not store service: {exc}")

    # -- reporting ---------------------------------------------------------- #
    def list_services(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return aggregated services from the database."""
        try:
            rows = self.db.query(
                "SELECT protocol, host, port, service, detail, COUNT(*) AS sightings, "
                "MIN(ts) AS first_seen, MAX(ts) AS last_seen "
                "FROM services GROUP BY protocol, host, port, service "
                "ORDER BY last_seen DESC LIMIT ?", (limit,))
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            self.logger.error(f"could not read the services database: {exc}")
            return []

    def render_list(self) -> str:
        """Render the recorded services as text."""
        rows = self.list_services()
        lines = [colour(f"  SERVICE WATCHER  ::  {now_iso()}", C.BRIGHT_CYAN), ""]
        if not rows:
            lines.append("  no services recorded yet - run: sudo cdeck services --duration 60")
            return "\n".join(lines)
        lines.append(f"  {'PROTOCOL':<9}{'HOST':<17}{'PORT':<7}{'SERVICE':<32}DETAIL")
        for row in rows:
            port = row["port"] or "-"
            detail = (row["detail"] or "").replace("\n", " ")[:44]
            lines.append(f"  {row['protocol']:<9}{row['host']:<17}{str(port):<7}"
                         f"{row['service'][:30]:<32}{detail}")
        protocols: Dict[str, int] = {}
        for row in rows:
            protocols[row["protocol"]] = protocols.get(row["protocol"], 0) + 1
        lines.append("")
        lines.append("  " + " · ".join(f"{name}: {count}" for name, count in
                                       sorted(protocols.items(), key=lambda kv: -kv[1])))
        return "\n".join(lines)

    def summary(self) -> Dict[str, Any]:
        """Return a machine-readable summary."""
        rows = self.list_services()
        return {
            "generated": now_iso(),
            "packets_observed": self.packet_count,
            "interface": self.interface,
            "services_found": len(self.entries),
            "services": rows,
            "warnings": self.warnings,
        }

    def close(self) -> None:
        """Close the database."""
        try:
            self.db.close()
        except sqlite3.Error:
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="service_watcher.py",
        description="passive mDNS/SSDP/LLMNR/NetBIOS service discovery",
        epilog="Also available as: cdeck services")
    parser.add_argument("-i", "--interface", default=None, help="interface to listen on")
    parser.add_argument("--duration", type=float, default=60.0,
                        help="listen for N seconds (default 60; 0 = until Ctrl-C)")
    parser.add_argument("--continuous", action="store_true", help="listen forever (service mode)")
    parser.add_argument("--from-service", action="store_true", help="service-mode logging")
    parser.add_argument("--list", action="store_true", help="list recorded services and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--multicast-only", action="store_true",
                        help="join multicast groups with sockets instead of sniffing")
    parser.add_argument("--version", action="version", version=f"service_watcher {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("service_watcher", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)),
                    quiet=args.from_service)

    watcher = ServiceWatcher(config, logger)
    if args.interface:
        watcher.interface = args.interface

    if args.list:
        print(json.dumps(watcher.summary(), indent=2, default=str) if args.json
              else watcher.render_list())
        watcher.close()
        return 0

    def handle_signal(_signum: int, _frame: Any) -> None:
        logger.info("signal received - stopping the watcher")
        watcher.running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    duration = None if args.continuous else (args.duration if args.duration and args.duration > 0 else None)

    if args.multicast_only:
        watcher.run_multicast_listener(duration)
    else:
        watcher.running = True
        sniffed = watcher.sniff(duration)
        if not sniffed:
            for warning in watcher.warnings:
                logger.warn(warning)
            logger.info("falling back to a multicast socket listener")
            watcher.running = True
            watcher.run_multicast_listener(duration)

    if args.json:
        print(json.dumps(watcher.summary(), indent=2, default=str))
    elif not args.from_service:
        logger.banner("service discovery complete",
                      f"{len(watcher.entries)} service(s) observed")
        print(watcher.render_list())
    watcher.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
