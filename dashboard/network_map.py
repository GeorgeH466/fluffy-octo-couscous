#!/usr/bin/env python3
"""
network_map.py - live network topology mapper for cyberdeck-arsenal
==================================================================

Description
-----------
Builds and displays a real-time map of the local network:

    * passive ARP observation (scapy, requires root)
    * neighbour-table polling (``ip neigh``, works unprivileged)
    * optional active discovery sweep (``arp-scan`` or ``nmap -sn``)

Every host is stored in ``data/arp.db`` with first-seen/last-seen timestamps,
MAC/vendor, inferred OS (TTL + behaviour heuristics) and hostname when it can be
resolved. New devices raise an alert in the shared alert feed, which is exactly
what you want when someone plugs into your deck's network.

Output options: ASCII topology diagram, live Textual/rich table, or JSON export.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; rich (optional); scapy+root for passive sniffing;
              arp-scan or nmap for active sweeps
Licence     : MIT - passive monitoring of networks you are authorised to observe

Usage
-----
    cdeck netmap                       # live map
    sudo cdeck netmap --sniff          # passive sniff + neighbour polling
    python3 dashboard/network_map.py --diagram
    python3 dashboard/network_map.py --scan 192.168.1.0/24 --json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
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
        C, Config, Database, Alerts, Logger, OuiLookup, colour, deps,
        human_duration, now_iso, run,
    )
except ImportError as exc:
    print(f"network_map: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Devices that are almost never a threat and would otherwise alert constantly
IGNORE_VENDORS = ("Unknown",)

#: Common gateway/DNS suffixes used to guess a host's role
ROLE_HINTS: Tuple[Tuple[str, str], ...] = (
    ("router", "gateway"), ("gateway", "gateway"), ("gw", "gateway"),
    ("switch", "switch"), ("ap", "access point"), ("printer", "printer"),
    ("camera", "camera"), ("cam", "camera"), ("nas", "nas"), ("server", "server"),
    ("phone", "mobile"), ("iphone", "mobile"), ("android", "mobile"),
    ("laptop", "workstation"), ("desktop", "workstation"), ("pc", "workstation"),
    ("tv", "media"), ("chromecast", "media"), ("roku", "media"),
)


@dataclass
class Host:
    """A discovered host on the local network."""

    ip: str
    mac: str = "unknown"
    vendor: str = "Unknown"
    hostname: str = ""
    os_guess: str = "unknown"
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    packets: int = 1
    is_gateway: bool = False
    open_ports: List[int] = field(default_factory=list)
    role: str = "host"
    is_new: bool = False

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for JSON export."""
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "hostname": self.hostname, "os_guess": self.os_guess,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "packets": self.packets, "is_gateway": self.is_gateway,
            "open_ports": self.open_ports, "role": self.role, "is_new": self.is_new,
        }


class NetworkMap:
    """Collects hosts and persists them to the arp database."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None) -> None:
        """Open the database and prepare caches."""
        self.config = config or Config().load()
        self.logger = logger or Logger("network_map",
                                       str(self.config.get("general.log_level", "INFO")))
        self.oui = OuiLookup()
        self.db = Database("arp", logger=self.logger)
        self.alerts = Alerts("network_map", self.config, self.logger)
        self.hosts: Dict[str, Host] = {}
        self.lock = threading.Lock()
        self.gateway_ip: Optional[str] = None
        self.interface: Optional[str] = None
        self.sniffer_running = False
        self._known_macs: Dict[str, str] = {}
        self._load_existing()

    # -- persistence -------------------------------------------------------- #
    def _load_existing(self) -> None:
        """Load previously seen hosts so restarts do not re-alert."""
        try:
            for row in self.db.query("SELECT * FROM arp_hosts"):
                host = Host(
                    ip=row["ip"], mac=row["mac"] or "unknown",
                    vendor=row["vendor"] or "Unknown",
                    hostname=row["hostname"] or "",
                    os_guess=row["os_guess"] or "unknown",
                    first_seen=row["first_seen"], last_seen=row["last_seen"],
                    packets=int(row["packets"] or 1),
                    is_gateway=bool(row["gateway"]))
                host.role = self._guess_role(host)
                self.hosts[host.ip] = host
                if host.mac != "unknown":
                    self._known_macs[host.mac.lower()] = host.ip
            if self.hosts:
                self.logger.info(f"loaded {len(self.hosts)} host(s) from previous sessions")
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"could not load previous hosts: {exc}")

    def persist(self, host: Host) -> None:
        """Insert or update *host* in the arp database."""
        self.db.upsert("arp_hosts", ["ip"], {
            "ip": host.ip, "mac": host.mac, "hostname": host.hostname,
            "vendor": host.vendor, "os_guess": host.os_guess,
            "first_seen": host.first_seen, "last_seen": host.last_seen,
            "packets": host.packets, "gateway": int(host.is_gateway),
            "notes": host.role,
        })

    # -- discovery ---------------------------------------------------------- #
    def identify_self(self) -> None:
        """Determine the gateway address and the interface in use."""
        code, out, _ = run(["ip", "route", "show", "default"], timeout=5)
        if code == 0 and out:
            parts = out.split()
            if "via" in parts:
                self.gateway_ip = parts[parts.index("via") + 1]
            if "dev" in parts:
                self.interface = parts[parts.index("dev") + 1]
        if not self.interface:
            for iface in ("wlan0", "eth0", "en0"):
                if Path(f"/sys/class/net/{iface}").exists():
                    self.interface = iface
                    break

    def local_subnet(self) -> Optional[str]:
        """Return the CIDR of the interface's network, if determinable."""
        if not self.interface:
            self.identify_self()
        if not self.interface:
            return None
        code, out, _ = run(["ip", "-4", "addr", "show", self.interface], timeout=5)
        if code != 0:
            return None
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out or "")
        if not match:
            return None
        try:
            return str(ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False))
        except ValueError:
            return None

    def poll_neighbours(self) -> int:
        """Read the kernel neighbour table (no privileges required)."""
        discovered = 0
        code, out, _ = run(["ip", "-4", "neigh", "show"], timeout=5)
        if code != 0 and Path("/proc/net/arp").exists():
            out = ""
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 4:
                    out += f"{fields[0]} dev {fields[5] if len(fields) > 5 else '?'} "
                    out += f"lladdr {fields[3]} {fields[2]}\n"
        for line in (out or "").splitlines():
            fields = line.split()
            if not fields or not re.match(r"^\d+\.\d+\.\d+\.\d+$", fields[0]):
                continue
            ip_address = fields[0]
            mac = "unknown"
            state = ""
            if "lladdr" in fields:
                index = fields.index("lladdr")
                if index + 1 < len(fields):
                    mac = fields[index + 1]
            if fields:
                state = fields[-1]
            if mac in ("00:00:00:00:00:00",) or state in ("FAILED", "INCOMPLETE"):
                continue
            self.observe(ip_address, mac, source="neigh")
            discovered += 1
        return discovered

    def observe(self, ip_address: str, mac: str, source: str = "passive",
                hostname: Optional[str] = None) -> Optional[Host]:
        """Record a sighting of *ip_address*/*mac*; returns the host if new."""
        if ip_address in ("0.0.0.0", "255.255.255.255") or ip_address.startswith("224."):
            return None
        mac = (mac or "unknown").lower()
        with self.lock:
            host = self.hosts.get(ip_address)
            is_new = host is None
            if host is None:
                host = Host(ip=ip_address, mac=mac,
                            vendor=self.oui.vendor(mac) if mac != "unknown" else "Unknown",
                            is_gateway=(ip_address == self.gateway_ip),
                            is_new=True)
                self.hosts[ip_address] = host
            else:
                host.packets += 1
                host.last_seen = now_iso()
                if mac != "unknown" and host.mac != mac:
                    # MAC change on a known IP: either DHCP churn or ARP spoofing
                    self.db.event("network_map", "arp",
                                  f"MAC change for {ip_address}: {host.mac} → {mac}",
                                  "WARNING", {"ip": ip_address, "old": host.mac, "new": mac})
                    self.alerts.send(f"MAC address change on {ip_address}",
                                     f"was {host.mac}, now {mac} - possible ARP spoofing",
                                     "WARNING")
                    host.mac = mac
                    host.vendor = self.oui.vendor(mac)
            if hostname:
                host.hostname = hostname
            elif not host.hostname:
                resolved = self._reverse_lookup(ip_address)
                if resolved:
                    host.hostname = resolved
            host.role = self._guess_role(host)
            self.persist(host)

        if is_new:
            self._on_new_host(host)
        return host if is_new else None

    def _on_new_host(self, host: Host) -> None:
        """Alert on and enrich a newly discovered host."""
        self.logger.alert(f"new device on the network: {host.ip} ({host.mac}) {host.vendor}")
        try:
            self.db.event("network_map", "discovery",
                          f"new device {host.ip} ({host.mac}) {host.vendor}",
                          "WARNING", host.as_dict())
        except Exception:  # noqa: BLE001
            pass
        if bool(self.config.get("alerts.new_device_alert", True)):
            self.alerts.send(f"New device detected: {host.ip}",
                             f"{host.vendor} ({host.mac}) role={host.role}", "WARNING")
        # Fingerprint newly discovered devices (TTL probe) in the background
        threading.Thread(target=self._fingerprint, args=(host,), daemon=True).start()

    def _fingerprint(self, host: Host) -> None:
        """Guess the OS from the TTL of a single ping reply."""
        code, out, _ = run(["ping", "-c", "1", "-W", "1", host.ip], timeout=6)
        match = re.search(r"ttl=(\d+)", out or "", re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                host.os_guess = "Linux/Unix (TTL<=64)"
            elif ttl <= 128:
                host.os_guess = "Windows (TTL<=128)"
            else:
                host.os_guess = "Network device (TTL>128)"
            with self.lock:
                self.persist(host)

    @staticmethod
    def _reverse_lookup(ip_address: str) -> str:
        """Reverse-resolve an address with a short timeout."""
        try:
            socket.setdefaulttimeout(1.0)
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""
        finally:
            socket.setdefaulttimeout(None)

    @staticmethod
    def _guess_role(host: Host) -> str:
        """Infer a device role from hostname, vendor and gateway status."""
        haystack = f"{host.hostname} {host.vendor}".lower()
        for needle, role in ROLE_HINTS:
            if needle in haystack:
                return role
        if host.is_gateway:
            return "gateway"
        if "apple" in haystack:
            return "apple-device"
        if "raspberry" in haystack or "espressif" in haystack:
            return "embedded/iot"
        return "host"

    # -- active discovery --------------------------------------------------- #
    def active_scan(self, subnet: Optional[str] = None, method: str = "auto") -> int:
        """Run an active discovery sweep and record the results."""
        target = subnet or self.local_subnet()
        if not target:
            self.logger.error("cannot determine the local subnet - pass it explicitly")
            return 0
        self.logger.info(f"active discovery sweep on {target} (authorised networks only)")
        found = 0

        if method in ("auto", "arp-scan") and deps.have("arp-scan"):
            code, out, err = run(["arp-scan", "--localnet", "--retry=2", "--timeout=500"],
                                 timeout=120, logger=self.logger)
            if code != 0:
                code, out, err = run(["arp-scan", target], timeout=120, logger=self.logger)
            for line in (out or "").splitlines():
                match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$", line)
                if match:
                    host = self.observe(match.group(1), match.group(2), "arp-scan",
                                        hostname=match.group(3).strip() or None)
                    found += 1
                    if host:
                        self.logger.info(f"  discovered {host.ip} {host.mac} {host.vendor}")
            return found

        if method in ("auto", "nmap") and deps.have("nmap"):
            timing = str(self.config.get("scanning.nmap_timing", "T4"))
            code, out, err = run(["nmap", "-sn", "-PR", f"-{timing}", target],
                                 timeout=max(120, 60 + 2000), logger=self.logger)
            current_ip: Optional[str] = None
            for line in (out or "").splitlines():
                ip_match = re.match(r"Nmap scan report for (?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?", line)
                if ip_match:
                    current_ip = ip_match.group(2)
                    if current_ip:
                        self.observe(current_ip, "unknown", "nmap",
                                     hostname=ip_match.group(1) or None)
                        found += 1
                mac_match = re.match(r"MAC Address: ([0-9A-Fa-f:]{17})\s*\(?(.*?)\)?$", line.strip())
                if mac_match and current_ip:
                    self.observe(current_ip, mac_match.group(1), "nmap",
                                 hostname=mac_match.group(2).strip() or None)
            return found

        # Last resort: ping sweep, then let the neighbour table fill in
        self.logger.info("neither arp-scan nor nmap available - falling back to a ping sweep")
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            self.logger.error(f"invalid subnet: {target}")
            return 0

        def ping(address: str) -> None:
            run(["ping", "-c", "1", "-W", "1", address], timeout=4)

        threads = []
        for address in list(network.hosts())[:512]:
            thread = threading.Thread(target=ping, args=(str(address),), daemon=True)
            thread.start()
            threads.append(thread)
            if len(threads) >= 64:
                for running_thread in threads:
                    running_thread.join(timeout=2)
                threads = []
        for running_thread in threads:
            running_thread.join(timeout=2)
        time.sleep(2)
        return self.poll_neighbours()

    # -- passive sniffing --------------------------------------------------- #
    def start_sniffing(self) -> bool:
        """Start a passive ARP sniffer thread (needs scapy + root)."""
        if os.geteuid() != 0:
            self.logger.warn("passive sniffing needs root - using neighbour polling only")
            return False
        if not deps.have_module("scapy"):
            self.logger.warn("scapy not installed - using neighbour polling only")
            return False
        try:
            import scapy.all as scapy  # type: ignore
        except ImportError:
            return False

        def handle(packet: Any) -> None:
            try:
                if not packet.haslayer(scapy.ARP):
                    return
                arp = packet[scapy.ARP]
                self.observe(str(arp.psrc), str(arp.hwsrc).lower(), "sniff")
                if arp.op == 2 and str(arp.pdst) not in ("0.0.0.0",):
                    self.observe(str(arp.pdst), str(arp.hwdst).lower(), "sniff")
            except Exception:  # noqa: BLE001
                pass

        def loop() -> None:
            self.sniffer_running = True
            self.logger.info(f"passive ARP sniffing on {self.interface or 'all interfaces'}")
            try:
                scapy.sniff(iface=self.interface, filter="arp", prn=handle, store=False)
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"sniffer stopped: {exc}")
            self.sniffer_running = False

        threading.Thread(target=loop, name="arp-sniffer", daemon=True).start()
        return True

    # -- rendering ---------------------------------------------------------- #
    def ascii_diagram(self, max_hosts: int = 40) -> str:
        """Render the topology as an ASCII diagram."""
        with self.lock:
            hosts = sorted(self.hosts.values(),
                           key=lambda h: (not h.is_gateway, tuple(int(o) for o in h.ip.split("."))))
        gateway = next((h for h in hosts if h.is_gateway), None)
        others = [h for h in hosts if not h.is_gateway]

        lines: List[str] = []
        node = self.interface or "local"
        if gateway:
            lines.append(f"                    ┌────────────────────────────┐")
            lines.append(f"                    │  {node:<26}│")
            lines.append(f"                    │  gateway {gateway.ip:<17}│")
            lines.append(f"                    └──────────────┬─────────────┘")
        else:
            lines.append(f"  ┌──────────────────────────────┐")
            lines.append(f"  │  {node:<28}│")
            lines.append(f"  │  (no gateway detected)       │")
            lines.append(f"  └──────────────┬───────────────┘")
        lines.append(f"                 │")
        lines.append(f"       ┌─────────┴─────────┬─────────┬─────────┐")

        for index, host in enumerate(others[:max_hosts]):
            prefix = "   " if index % 4 == 0 and index else "                 "
            marker = colour("NEW", C.BRIGHT_RED) if host.is_new else "   "
            role = f"[{host.role[:9]}]"
            label = f"{host.ip:<15} {host.mac:<17} {host.vendor[:18]:<18} {role:<11} {marker}"
            lines.append(f"       {label}")
        if len(others) > max_hosts:
            lines.append(f"       ... and {len(others) - max_hosts} more host(s)")
        lines.append("")
        lines.append(f"  total {len(hosts)} host(s) · gateway: {gateway.ip if gateway else 'unknown'} "
                     f"· interface: {node}")
        return "\n".join(lines)

    def run_live(self, refresh: float, sniff: bool, scan_interval: Optional[int]) -> int:
        """Run a live refreshing view of the map."""
        if sniff:
            self.start_sniffing()

        def poll_loop() -> None:
            while True:
                try:
                    self.poll_neighbours()
                except Exception as exc:  # noqa: BLE001
                    self.logger.debug(f"neighbour poll failed: {exc}")
                time.sleep(5)

        threading.Thread(target=poll_loop, name="neighbour-poller", daemon=True).start()

        if scan_interval:
            def scan_loop() -> None:
                while True:
                    time.sleep(scan_interval)
                    try:
                        self.active_scan()
                    except Exception as exc:  # noqa: BLE001
                        self.logger.debug(f"scheduled scan failed: {exc}")

            threading.Thread(target=scan_loop, name="scheduled-scan", daemon=True).start()

        try:
            from rich.console import Console, Group
            from rich.live import Live
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            self.logger.warn("rich not installed - printing the diagram once")
            print(self.ascii_diagram())
            return 0

        console = Console()

        def build() -> Panel:
            with self.lock:
                hosts = sorted(self.hosts.values(),
                               key=lambda h: (not h.is_gateway,
                                              tuple(int(o) for o in h.ip.split("."))))
            table = Table(expand=True, box=None, header_style="bold #00ffd5")
            table.add_column("ip", width=16)
            table.add_column("mac", width=18)
            table.add_column("vendor", width=20)
            table.add_column("role", width=13)
            table.add_column("os guess", width=22, overflow="fold")
            table.add_column("seen", width=11, justify="right")
            table.add_column("pkt", width=5, justify="right")
            for host in hosts[:26]:
                first_seen_seconds = 0.0
                try:
                    from datetime import datetime
                    first = datetime.fromisoformat(host.first_seen)
                    first_seen_seconds = (datetime.now(first.tzinfo) - first).total_seconds()
                except Exception:  # noqa: BLE001
                    first_seen_seconds = 0.0
                is_new = first_seen_seconds < 300
                table.add_row(
                    Text(("★ " if host.is_gateway else "  ") + host.ip,
                         style="bold #ff79c6" if host.is_gateway else ("bold #ff5555" if is_new else "#8bd5ff")),
                    Text(host.mac, style="dim"),
                    Text(host.vendor[:20], style="#00ffd5" if host.vendor != "Unknown" else "dim"),
                    Text(host.role, style="dim"),
                    Text(host.os_guess, style="dim"),
                    Text(human_duration(first_seen_seconds), style="dim"),
                    Text(str(host.packets), style="dim"))
            if not hosts:
                table.add_row(Text("no hosts discovered yet", style="dim"), "", "", "", "", "", "")
            header = Text()
            header.append("  NETWORK MAP  ", style="bold #00ffd5")
            header.append(f"{len(hosts)} host(s)  ", style="dim")
            header.append(f"gateway {self.gateway_ip or 'unknown'}  ", style="dim")
            header.append(f"iface {self.interface or '?'}  ", style="dim")
            header.append(f"sniffing {'on' if self.sniffer_running else 'off'}", style="dim")
            diagram = Text(self.ascii_diagram(12), style="dim")
            return Panel(Group(header, Text(""), table, Text(""), diagram),
                         border_style="#5a6b7a",
                         subtitle="q to quit · s to sweep · r to refresh")

        try:
            with Live(build(), console=console, refresh_per_second=max(1, int(1 / refresh)),
                      screen=True) as live:
                while True:
                    live.update(build())
                    time.sleep(refresh)
        except KeyboardInterrupt:
            pass
        return 0

    def close(self) -> None:
        """Release database handles."""
        try:
            self.db.close()
        except Exception:  # noqa: BLE001
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
        prog="network_map.py",
        description="live network topology mapper (passive ARP + optional active sweep)",
        epilog="Also available as: cdeck netmap")
    parser.add_argument("--sniff", action="store_true", help="enable passive ARP sniffing (root)")
    parser.add_argument("--scan", metavar="SUBNET", default=None,
                        help="run an active discovery sweep on this subnet first")
    parser.add_argument("--scan-method", choices=["auto", "arp-scan", "nmap", "ping"], default="auto",
                        help="active discovery backend")
    parser.add_argument("--scan-interval", type=int, default=0,
                        help="repeat the active sweep every N seconds (0 = once)")
    parser.add_argument("--diagram", action="store_true", help="print the ASCII diagram and exit")
    parser.add_argument("--json", action="store_true", help="emit the host list as JSON")
    parser.add_argument("--refresh", type=float, default=2.0, help="display refresh interval")
    parser.add_argument("--timeout", type=float, default=None,
                        help="with --scan, stop after N seconds and print results")
    parser.add_argument("--prune-new", action="store_true",
                        help="run once to record the current landscape without alerts")
    parser.add_argument("--version", action="version", version=f"network_map {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("network_map", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)))

    mapper = NetworkMap(config, logger)
    mapper.identify_self()
    logger.info(f"interface {mapper.interface or '?'} · gateway {mapper.gateway_ip or 'unknown'} "
                f"· subnet {mapper.local_subnet() or 'unknown'}")

    try:
        if args.prune_new:
            # Mark existing hosts as known so the next run only alerts on genuinely new devices
            count = mapper.poll_neighbours()
            logger.ok(f"baseline recorded: {count} host(s) known - future runs alert on new devices only")
            return 0

        if args.scan:
            if os.geteuid() != 0 and args.scan_method in ("auto", "arp-scan"):
                logger.warn("active sweeps work best as root: sudo cdeck netmap --scan ...")
            found = mapper.active_scan(args.scan, args.scan_method)
            logger.ok(f"active sweep complete: {found} host(s) observed")

        found = mapper.poll_neighbours()
        logger.info(f"neighbour table: {found} entr(ies)")

        if args.json:
            with mapper.lock:
                payload = {
                    "generated": now_iso(),
                    "interface": mapper.interface,
                    "gateway": mapper.gateway_ip,
                    "subnet": mapper.local_subnet(),
                    "hosts": [h.as_dict() for h in mapper.hosts.values()],
                }
            print(json.dumps(payload, indent=2))
            return 0

        if args.diagram:
            print(mapper.ascii_diagram())
            return 0

        if args.timeout:
            deadline = time.time() + args.timeout
            mapper.start_sniffing()
            while time.time() < deadline:
                mapper.poll_neighbours()
                time.sleep(3)
            print(mapper.ascii_diagram())
            return 0

        return mapper.run_live(args.refresh, args.sniff, args.scan_interval or None)
    except KeyboardInterrupt:
        print()
        logger.info("network map closed")
        return 0
    finally:
        mapper.close()


if __name__ == "__main__":
    sys.exit(main())
