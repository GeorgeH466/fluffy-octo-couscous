#!/usr/bin/env python3
"""
arp_mapper.py - passive ARP landscape mapping
=============================================

Description
-----------
Sniffs ARP traffic with scapy (or reads the kernel neighbour table when scapy
or root is unavailable) and builds a persistent picture of the local network:
who is present, what they claim to be, and how the OS behaves.

OS identification heuristics used here:
    * ARP request behaviour (who talks first, who answers for the gateway)
    * gratuitous ARP usage and timing
    * gateway impersonation attempts (ARP cache poisoning detection)
    * TTL of ICMP replies for hosts that respond to a polite single ping

Outputs:
    * ``data/arp.db``  - hosts and events, shared with the HUD and network map
    * JSON export      - ``--json`` or ``--export-json PATH``
    * Graphviz DOT     - ``--export-dot PATH`` for visual topology diagrams
    * ASCII diagram    - ``--diagram``

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; scapy (optional, root for live sniffing); graphviz binary
              only needed to render the DOT file into an image
Licence     : MIT - passive monitoring of networks you are authorised to observe

Usage
-----
    sudo cdeck arp --duration 120
    python3 recon/passive/arp_mapper.py --neighbours          # no root needed
    python3 recon/passive/arp_mapper.py --diagram
    python3 recon/passive/arp_mapper.py --export-dot /tmp/net.dot
    python3 recon/passive/arp_mapper.py --detect-spoofing
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
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
        C, Config, Database, Hardware, Logger, OuiLookup, colour, deps,
        human_duration, now_iso, read_json, run, write_json,
    )
except ImportError as exc:
    print(f"arp_mapper: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"


@dataclass
class ArpHost:
    """A host observed on the local network."""

    ip: str
    mac: str = "unknown"
    vendor: str = "Unknown"
    hostname: str = ""
    os_guess: str = "unknown"
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    packets: int = 1
    is_gateway: bool = False
    arp_requests: int = 0
    arp_replies: int = 0
    gratuitous: int = 0
    ttl: Optional[int] = None
    suspicion: int = 0
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise the host for JSON/DOT export."""
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "hostname": self.hostname, "os_guess": self.os_guess,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "packets": self.packets, "is_gateway": self.is_gateway,
            "arp_requests": self.arp_requests, "arp_replies": self.arp_replies,
            "gratuitous": self.gratuitous, "ttl": self.ttl,
            "suspicion": self.suspicion, "notes": self.notes,
        }


class ArpMapper:
    """Sniffs ARP and maintains the host map."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None) -> None:
        """Open the arp database and load previously known hosts."""
        self.config = config or Config().load()
        self.logger = logger or Logger("arp_mapper",
                                       str(self.config.get("general.log_level", "INFO")))
        self.oui = OuiLookup()
        self.db = Database("arp", logger=self.logger)
        self.hosts: Dict[str, ArpHost] = {}
        self.mac_to_ip: Dict[str, List[str]] = {}
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.interface: Optional[str] = None
        self.lock = threading.Lock()
        self.running = False
        self.events: List[str] = []
        self._load()

    # -- setup -------------------------------------------------------------- #
    def _load(self) -> None:
        """Load persisted hosts and detect the gateway."""
        try:
            for row in self.db.query("SELECT * FROM arp_hosts"):
                host = ArpHost(
                    ip=row["ip"], mac=row["mac"] or "unknown",
                    vendor=row["vendor"] or "Unknown", hostname=row["hostname"] or "",
                    os_guess=row["os_guess"] or "unknown",
                    first_seen=row["first_seen"], last_seen=row["last_seen"],
                    packets=int(row["packets"] or 1), is_gateway=bool(row["gateway"]))
                self.hosts[host.ip] = host
                self.mac_to_ip.setdefault(host.mac, []).append(host.ip)
                if host.is_gateway:
                    self.gateway_ip = host.ip
                    self.gateway_mac = host.mac
        except sqlite3.Error as exc:
            self.logger.debug(f"no previous host data: {exc}")
        code, out, _ = run(["ip", "route", "show", "default"], timeout=5)
        if code == 0 and out:
            parts = out.split()
            if "via" in parts:
                self.gateway_ip = parts[parts.index("via") + 1]
            if "dev" in parts:
                self.interface = parts[parts.index("dev") + 1]
        if self.gateway_ip:
            self.logger.info(f"gateway {self.gateway_ip} via {self.interface or '?'}")

    # -- capture ------------------------------------------------------------ #
    def sniff(self, duration: Optional[float], detect_spoofing: bool = True) -> bool:
        """Passively sniff ARP packets for *duration* seconds."""
        if os.geteuid() != 0:
            self.logger.error("ARP sniffing requires root: sudo cdeck arp")
            return False
        try:
            from scapy.all import ARP, sniff as scapy_sniff  # type: ignore
        except ImportError:
            self.logger.error("scapy is not installed (pip install scapy)")
            return False

        self.logger.info(f"sniffing ARP on {self.interface or 'all interfaces'}"
                         + (f" for {duration:.0f}s" if duration else ""))
        self.running = True

        def handler(packet: Any) -> None:
            try:
                if not packet.haslayer(ARP):
                    return
                arp = packet[ARP]
                self.observe(str(arp.psrc), str(arp.hwsrc).lower(), op=int(arp.op),
                             gratuitous=(str(arp.psrc) == str(arp.pdst)),
                             detect_spoofing=detect_spoofing)
                if int(arp.op) == 2 and str(arp.pdst) not in ("0.0.0.0", ""):
                    self.observe(str(arp.pdst), str(arp.hwdst).lower(), op=2,
                                 detect_spoofing=detect_spoofing)
            except Exception as exc:  # noqa: BLE001 - the sniffer must not die
                self.logger.debug(f"ARP parse error: {exc}")

        try:
            scapy_sniff(iface=self.interface, filter="arp", prn=handler, store=False,
                        timeout=duration,
                        stop_filter=lambda _p: not self.running)
        except KeyboardInterrupt:
            self.logger.info("sniffing interrupted")
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"sniffing failed: {exc}")
            return False
        finally:
            self.running = False
        return True

    def observe(self, ip_address: str, mac: str, op: int = 1, gratuitous: bool = False,
                detect_spoofing: bool = True) -> Optional[ArpHost]:
        """Record an ARP sighting; returns the host when it is new."""
        if not ip_address or ip_address in ("0.0.0.0", "255.255.255.255"):
            return None
        mac = (mac or "unknown").lower()
        is_new = False
        with self.lock:
            host = self.hosts.get(ip_address)
            if host is None:
                is_new = True
                host = ArpHost(
                    ip=ip_address, mac=mac,
                    vendor=self.oui.vendor(mac) if mac != "unknown" else "Unknown",
                    is_gateway=(ip_address == self.gateway_ip))
                self.hosts[ip_address] = host
                self.mac_to_ip.setdefault(mac, []).append(ip_address)
                if host.is_gateway:
                    self.gateway_mac = mac
            else:
                host.packets += 1
                host.last_seen = now_iso()
            if op == 1:
                host.arp_requests += 1
            else:
                host.arp_replies += 1
            if gratuitous:
                host.gratuitous += 1
            if mac != "unknown" and host.mac != mac and host.mac != "unknown":
                host.suspicion += 5
                host.notes.append(f"MAC changed {host.mac} → {mac} at {now_iso()}")
                self._event(host.ip, mac, "mac-change",
                            f"{host.ip} changed MAC from {host.mac} to {mac}")
                host.mac = mac
                host.vendor = self.oui.vendor(mac)
            self._persist(host)

        if is_new:
            self.logger.alert(f"new ARP host: {host.ip} ({host.mac}) {host.vendor}")
            self._event(host.ip, host.mac, "new-host", f"new host {host.ip}")

        if detect_spoofing:
            self._check_spoofing(host, op)
        return host if is_new else None

    def _check_spoofing(self, host: ArpHost, op: int) -> None:
        """Detect classic ARP cache poisoning patterns."""
        # 1. A non-gateway MAC claiming the gateway's IP
        if self.gateway_ip and host.ip == self.gateway_ip and self.gateway_mac \
                and host.mac != self.gateway_mac and host.mac != "unknown":
            host.suspicion += 10
            self.logger.alert(f"gateway IP {host.ip} now answered by {host.mac} "
                              f"(expected {self.gateway_mac}) - possible ARP spoofing")
            self._event(host.ip, host.mac, "gateway-spoof",
                        "gateway impersonation detected")
        # 2. One MAC claiming many IPs in a short window
        with self.lock:
            claimed = self.mac_to_ip.get(host.mac, [])
        if len(claimed) > 8:
            host.suspicion += 3
            note = f"MAC {host.mac} claims {len(claimed)} IP addresses"
            if note not in host.notes:
                host.notes.append(note)
                self.logger.warn(note + " - possible ARP scan or proxy ARP")
        # 3. Gratuitous ARP storms (often a sign of a spoofing tool or a broken NIC)
        if host.gratuitous > 20:
            note = f"{host.ip} has sent {host.gratuitous} gratuitous ARPs"
            if note not in host.notes:
                host.notes.append(note)
                self.logger.warn(note)

    def _persist(self, host: ArpHost) -> None:
        """Write the host to SQLite."""
        try:
            self.db.upsert("arp_hosts", ["ip"], {
                "ip": host.ip, "mac": host.mac, "hostname": host.hostname,
                "vendor": host.vendor, "os_guess": host.os_guess,
                "first_seen": host.first_seen, "last_seen": host.last_seen,
                "packets": host.packets, "gateway": int(host.is_gateway),
                "notes": "; ".join(host.notes[-5:]),
            })
        except sqlite3.Error as exc:
            self.logger.debug(f"could not persist {host.ip}: {exc}")

    def _event(self, ip_address: str, mac: str, kind: str, detail: str) -> None:
        """Append to the ARP event log and the shared event feed."""
        entry = f"{now_iso()} [{kind}] {detail}"
        self.events.append(entry)
        try:
            self.db.execute("INSERT INTO arp_events (ts, ip, mac, event, detail) VALUES (?,?,?,?,?)",
                            (now_iso(), ip_address, mac, kind, detail))
            severity = "ALERT" if kind in ("gateway-spoof", "mac-change") else "INFO"
            self.db.event("arp_mapper", "arp", detail, severity,
                          {"ip": ip_address, "mac": mac})
        except sqlite3.Error as exc:
            self.logger.debug(f"could not record event: {exc}")

    # -- enrichment --------------------------------------------------------- #
    def poll_neighbours(self, enrich: bool = False) -> int:
        """Import the kernel neighbour table; optionally resolve names/TTLs."""
        discovered = 0
        code, out, _ = run(["ip", "-4", "neigh", "show"], timeout=5)
        if code != 0:
            return 0
        for line in (out or "").splitlines():
            fields = line.split()
            if not fields:
                continue
            ip_address = fields[0]
            mac = "unknown"
            if "lladdr" in fields:
                index = fields.index("lladdr")
                if index + 1 < len(fields):
                    mac = fields[index + 1]
            if mac == "unknown" or fields[-1] in ("FAILED", "INCOMPLETE"):
                continue
            host = self.observe(ip_address, mac, op=2, detect_spoofing=False)
            discovered += 1
            if enrich and host:
                self.enrich(host)
        return discovered

    def enrich(self, host: ArpHost) -> None:
        """Resolve the hostname and guess the OS from the ICMP TTL."""
        try:
            import socket
            socket.setdefaulttimeout(1.0)
            host.hostname = host.hostname or socket.gethostbyaddr(host.ip)[0]
        except Exception:  # noqa: BLE001
            pass
        finally:
            import socket as _socket
            _socket.setdefaulttimeout(None)

        code, out, _ = run(["ping", "-c", "1", "-W", "1", host.ip], timeout=5)
        import re
        match = re.search(r"ttl=(\d+)", out or "", re.IGNORECASE)
        if match:
            host.ttl = int(match.group(1))
            if host.ttl <= 64:
                host.os_guess = "Linux/Unix/BSD (TTL<=64)"
            elif host.ttl <= 128:
                host.os_guess = "Windows (TTL<=128)"
            else:
                host.os_guess = "network appliance (TTL>128)"
        self._persist(host)

    # -- exports ------------------------------------------------------------ #
    def ascii_diagram(self) -> str:
        """Render an ASCII topology diagram of the map."""
        with self.lock:
            hosts = sorted(self.hosts.values(),
                           key=lambda h: (not h.is_gateway,
                                          tuple(int(o) for o in h.ip.split(".") if o.isdigit())
                                          if h.ip.count(".") == 3 else (0,)))
        gateway = next((h for h in hosts if h.is_gateway), None)
        lines = [colour("  ARP LANDSCAPE MAP", C.BOLD), ""]
        lines.append("        ┌───────────────────────────────┐")
        node = self.interface or "local"
        lines.append(f"        │  deck interface {node:<13}│")
        if gateway:
            lines.append(f"        │  gateway {gateway.ip:<20}│")
            lines.append(f"        │  {gateway.mac:<17} {gateway.vendor[:11]:<11}│")
        lines.append("        └───────────────┬───────────────┘")
        lines.append("                        │")
        for host in hosts:
            if host.is_gateway:
                continue
            suspicion = colour("⚠", C.BRIGHT_RED) if host.suspicion > 3 else " "
            label = (f"{host.ip:<15} {host.mac:<17} {host.vendor[:20]:<20} "
                     f"{host.os_guess[:18]:<18} pkt:{host.packets:<5}{suspicion}")
            lines.append(f"        ├── {label}")
        lines.append("")
        lines.append(f"  {len(hosts)} host(s) mapped · {len(self.events)} event(s) this session")
        return "\n".join(lines)

    def export_json(self, path: Path) -> Path:
        """Write the map to JSON."""
        with self.lock:
            payload = {
                "generated": now_iso(),
                "interface": self.interface,
                "gateway": self.gateway_ip,
                "hosts": [host.as_dict() for host in self.hosts.values()],
                "events": self.events,
            }
        return write_json(Path(path), payload)

    def export_dot(self, path: Path) -> Path:
        """Write a Graphviz DOT description of the network."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            hosts = list(self.hosts.values())
        lines = [
            "digraph cyberdeck_network {",
            '  graph [bgcolor="#101418", fontname="monospace", label="cyberdeck-arsenal network map", labelloc="t"];',
            '  node [shape=box, style="rounded,filled", fillcolor="#1a2028", color="#00ffd5", fontcolor="#8bd5ff", fontname="monospace"];',
            '  edge [color="#5a6b7a"];',
        ]
        node_id = 0

        def identifier() -> str:
            nonlocal node_id
            node_id += 1
            return f"n{node_id}"

        deck_id = identifier()
        lines.append(f'  {deck_id} [label="deck\\n{self.interface or "local"}", fillcolor="#0f2b36"];')

        gateway = next((h for h in hosts if h.is_gateway), None)
        gateway_id: Optional[str] = None
        if gateway:
            gateway_id = identifier()
            lines.append(f'  {gateway_id} [label="GATEWAY\\n{gateway.ip}\\n{gateway.mac}", '
                         f'fillcolor="#2b1a36", color="#ff79c6"];')
            lines.append(f"  {deck_id} -> {gateway_id};")

        for host in hosts:
            if host.is_gateway:
                continue
            host_id = identifier()
            fill = "#3a1f1f" if host.suspicion > 3 else "#1a2028"
            colour_code = "#ff5555" if host.suspicion > 3 else "#00ffd5"
            label = (f"{host.ip}\\n{host.mac}\\n{host.vendor[:18]}\\n"
                     f"{host.os_guess[:18]}\\n{host.packets} pkt")
            lines.append(f'  {host_id} [label="{label}", fillcolor="{fill}", color="{colour_code}"];')
            parent = gateway_id or deck_id
            lines.append(f"  {parent} -> {host_id};")
        lines.append("}")
        path.write_text("\n".join(lines) + "\n")
        self.logger.ok(f"DOT graph written to {path}")
        if deps.have("dot"):
            self.logger.info(f"render it with: dot -Tpng {path} -o {path.with_suffix('.png')}")
        else:
            self.logger.info("install graphviz to render the DOT file into an image")
        return path

    # -- reporting ---------------------------------------------------------- #
    def render_report(self) -> str:
        """Render a textual report of the map."""
        self.poll_neighbours()
        with self.lock:
            hosts = sorted(self.hosts.values(),
                           key=lambda h: (not h.is_gateway,
                                          tuple(int(o) for o in h.ip.split(".")) if
                                          h.ip.count(".") == 3 else (0,)))
        lines = [
            colour(f"  ARP MAPPER  ::  {now_iso()}", C.BRIGHT_CYAN),
            "",
            colour("  HOSTS", C.BOLD),
            f"  {'IP':<16}{'MAC':<19}{'VENDOR':<22}{'OS GUESS':<26}{'PACKETS':>8}",
        ]
        for host in hosts:
            marker = "★ " if host.is_gateway else ("⚠ " if host.suspicion > 3 else "  ")
            lines.append(f"  {marker}{host.ip:<14}{host.mac:<19}{host.vendor[:20]:<22}"
                         f"{host.os_guess[:24]:<26}{host.packets:>8}")
            for note in host.notes[-3:]:
                lines.append(colour(f"      {note}", C.DIM))
        lines.append("")
        lines.append(self.ascii_diagram())
        if self.events:
            lines.append("")
            lines.append(colour("  EVENTS", C.BOLD))
            for event in self.events[-20:]:
                lines.append(f"  {event}")
        suspicious = [h for h in hosts if h.suspicion > 3]
        if suspicious:
            lines.append("")
            lines.append(colour("  ⚠ SUSPICIOUS ACTIVITY", C.BRIGHT_RED))
            for host in suspicious:
                lines.append(f"  {host.ip} ({host.mac}) suspicion={host.suspicion} "
                             f"- {'; '.join(host.notes[-2:])}")
        return "\n".join(lines)

    def summary(self) -> Dict[str, Any]:
        """Return a machine-readable summary."""
        with self.lock:
            hosts = list(self.hosts.values())
        return {
            "generated": now_iso(),
            "interface": self.interface,
            "gateway": self.gateway_ip,
            "host_count": len(hosts),
            "suspicious": [h.ip for h in hosts if h.suspicion > 3],
            "hosts": [h.as_dict() for h in hosts],
            "events": self.events[-50:],
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
        prog="arp_mapper.py",
        description="passive ARP landscape mapping with OS heuristics and spoof detection",
        epilog="Also available as: cdeck arp")
    parser.add_argument("--duration", type=float, default=60.0,
                        help="sniffing duration in seconds (default 60; 0 = until Ctrl-C)")
    parser.add_argument("--neighbours", action="store_true",
                        help="import the kernel neighbour table instead of sniffing (no root)")
    parser.add_argument("--detect-spoofing", action="store_true", default=True,
                        help="enable ARP spoofing heuristics (default on)")
    parser.add_argument("--no-spoof-check", action="store_true",
                        help="disable spoofing heuristics")
    parser.add_argument("--diagram", action="store_true", help="print the ASCII diagram and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--export-json", metavar="PATH", default=None,
                        help="write the map to a JSON file")
    parser.add_argument("--export-dot", metavar="PATH", default=None,
                        help="write a Graphviz DOT file of the topology")
    parser.add_argument("--enrich", action="store_true",
                        help="resolve hostnames and TTL-based OS guesses (sends 1 ICMP per host)")
    parser.add_argument("--quiet", action="store_true", help="suppress the summary output")
    parser.add_argument("--version", action="version", version=f"arp_mapper {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("arp_mapper", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)), quiet=args.quiet)

    mapper = ArpMapper(config, logger)

    def handle_signal(_signum: int, _frame: Any) -> None:
        logger.info("signal received - stopping the mapper")
        mapper.running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        if not args.neighbours:
            duration = args.duration if args.duration and args.duration > 0 else None
            sniffed = mapper.sniff(duration, not args.no_spoof_check)
            if not sniffed:
                logger.info("falling back to the kernel neighbour table")
        mapper.poll_neighbours(enrich=args.enrich)

        if args.export_json:
            path = mapper.export_json(Path(args.export_json))
            logger.ok(f"JSON map written to {path}")
        if args.export_dot:
            mapper.export_dot(Path(args.export_dot))

        if args.diagram:
            print(mapper.ascii_diagram())
        elif args.json:
            print(json.dumps(mapper.summary(), indent=2, default=str))
        elif not args.quiet:
            print(mapper.render_report())

        suspicious = [h for h in mapper.hosts.values() if h.suspicion > 3]
        if suspicious:
            try:
                mapper.db.event("arp_mapper", "security",
                                f"{len(suspicious)} host(s) with suspicious ARP behaviour",
                                "ALERT", {"hosts": [h.ip for h in suspicious]})
            except sqlite3.Error:
                pass
        return 0
    except KeyboardInterrupt:
        logger.info("interrupted")
        return 130
    finally:
        mapper.close()


if __name__ == "__main__":
    sys.exit(main())
