#!/usr/bin/env python3
"""
packet_weather.py - live packet capture visualisation for cyberdeck-arsenal
==========================================================================

Description
-----------
Turns raw network traffic into a readable "weather report": protocol mix,
packets per second, bandwidth estimate, top talkers and a live packet ticker.

Data source preference:
    1. ``tshark``  (wireshark-cli) - field extraction, line buffered
    2. ``scapy``   - in-process capture when tshark/dumpcap is unavailable
    3. offline pcap replay with ``--read`` for demos and report screenshots

The tool is purely passive: it never transmits and never modifies traffic.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; rich (optional, CLI fallback); tshark or scapy+root
Licence     : MIT - passive monitoring of networks you are authorised to observe

Usage
-----
    cdeck packets
    python3 dashboard/packet_weather.py --interface eth0 --refresh 1
    python3 dashboard/packet_weather.py --read capture.pcapng --duration 30
    sudo python3 dashboard/packet_weather.py --once      # text snapshot
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

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
        C, Config, Database, Hardware, Logger, colour, deps, human_bytes, now_iso, run,
    )
except ImportError as exc:
    print(f"packet_weather: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Port-to-protocol labels for traffic tshark cannot name directly
PORT_PROTOCOLS: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "KERBEROS", 110: "POP3",
    123: "NTP", 135: "MSRPC", 137: "NETBIOS", 139: "NETBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    587: "SMTP", 631: "IPP", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OPENVPN", 1433: "MSSQL", 1521: "ORACLE", 1701: "L2TP", 1723: "PPTP",
    1900: "SSDP", 2049: "NFS", 3306: "MYSQL", 3389: "RDP", 4500: "IPSEC-NAT",
    5060: "SIP", 5222: "XMPP", 5353: "MDNS", 5432: "POSTGRES", 5900: "VNC",
    5985: "WINRM", 6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    9001: "TOR-OR", 9050: "TOR-SOCKS", 9040: "TOR-TRANS", 11211: "MEMCACHED",
    27017: "MONGODB",
}

#: Colour mapping for the protocol chart
PROTOCOL_COLOURS: Dict[str, str] = {
    "TCP": "#8bd5ff", "UDP": "#00ffd5", "ICMP": "#ffb86c", "ICMPv6": "#ffb86c",
    "ARP": "#ff79c6", "DNS": "#50fa7b", "HTTP": "#f1fa8c", "HTTPS": "#bd93f9",
    "SSH": "#ff5555", "TLS": "#bd93f9", "MDNS": "#8be9fd", "DHCP": "#ffb86c",
    "SMB": "#ff79c6", "QUIC": "#bd93f9", "SSDP": "#8be9fd", "NTP": "#6272a4",
    "TCP-OTH": "#8bd5ff",
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Packet:
    """A single summarised packet."""

    timestamp: float
    src: str = "?"
    dst: str = "?"
    protocol: str = "TCP"
    length: int = 0
    sport: Optional[int] = None
    dport: Optional[int] = None
    info: str = ""

    def classify(self) -> str:
        """Refine the protocol using well-known ports when tshark is vague."""
        protocol = (self.protocol or "").upper()
        if protocol in ("", "UNKNOWN", "DATA"):
            protocol = "TCP"
        # Map tshark's short names onto friendlier buckets
        aliases = {
            "TLSV1.2": "TLS", "TLSV1.3": "TLS", "SSL": "TLS",
            "MDNS": "MDNS", "LLMNR": "LLMNR", "NBNS": "NETBIOS",
            "HTTP2": "HTTPS", "HTTP/XML": "HTTP", "HTTP-JSON": "HTTP",
            "ICMPV6": "ICMPv6", "IGMP": "IGMP", "GRE": "GRE",
        }
        if protocol in aliases:
            protocol = aliases[protocol]
        if protocol in ("TCP",) and self.dport:
            protocol = PORT_PROTOCOLS.get(self.dport, protocol)
        if protocol == "UDP" and self.dport:
            protocol = PORT_PROTOCOLS.get(self.dport, protocol)
        if protocol == "TCP" and self.dport in PORT_PROTOCOLS:
            protocol = PORT_PROTOCOLS[self.dport]
        if protocol.endswith("_") or len(protocol) > 10:
            protocol = protocol[:10]
        return protocol


class Stats:
    """Thread-safe rolling statistics for the packet stream."""

    def __init__(self, window_seconds: int = 60) -> None:
        """Create a statistics window covering *window_seconds* seconds."""
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        self.packets: Deque[Packet] = collections.deque(maxlen=20000)
        self.total_packets = 0
        self.total_bytes = 0
        self.started = time.time()
        self._bucket_pps: Deque[Tuple[float, int, int]] = collections.deque(maxlen=window_seconds * 4)
        self._second_accumulator = {"second": int(time.time()), "packets": 0, "bytes": 0}
        self.talkers: Dict[str, Dict[str, int]] = {}
        self.conversations: Dict[str, Dict[str, int]] = {}
        self.anomalies: Deque[str] = collections.deque(maxlen=20)

    # -- ingest ------------------------------------------------------------- #
    def add(self, packet: Packet) -> None:
        """Record a packet (called from the capture thread)."""
        with self.lock:
            self.packets.append(packet)
            self.total_packets += 1
            self.total_bytes += packet.length
            second = int(packet.timestamp)
            if second != self._second_accumulator["second"]:
                self._bucket_pps.append((self._second_accumulator["second"],
                                         self._second_accumulator["packets"],
                                         self._second_accumulator["bytes"]))
                self._second_accumulator = {"second": second, "packets": 0, "bytes": 0}
            self._second_accumulator["packets"] += 1
            self._second_accumulator["bytes"] += packet.length

            if packet.src and packet.src not in ("?", "0.0.0.0"):
                entry = self.talkers.setdefault(packet.src, {"sent": 0, "bytes_out": 0})
                entry["sent"] += 1
                entry["bytes_out"] += packet.length
            if packet.dst and packet.dst not in ("?", "0.0.0.0"):
                entry = self.talkers.setdefault(packet.dst, {"sent": 0, "bytes_out": 0})
                entry.setdefault("received", 0)
                entry["received"] = entry.get("received", 0) + 1

            key = f"{packet.src} → {packet.dst}"
            conversation = self.conversations.setdefault(key, {"packets": 0, "bytes": 0})
            conversation["packets"] += 1
            conversation["bytes"] += packet.length

            # Cheap anomaly heuristics: worth surfacing in the ticker
            if packet.protocol in ("ARP",) and "gratuitous" in packet.info.lower():
                self.anomalies.append(f"{now_iso()} gratuitous ARP from {packet.src}")
            if packet.dport == 5353 and packet.length > 1200:
                self.anomalies.append(f"{now_iso()} oversized mDNS from {packet.src}")

    # -- queries ------------------------------------------------------------ #
    def reset(self) -> None:
        """Clear all counters (used when rotating the display window)."""
        with self.lock:
            self.packets.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self._bucket_pps.clear()
            self.talkers.clear()
            self.conversations.clear()
            self.started = time.time()

    def protocol_distribution(self) -> List[Tuple[str, int, int]]:
        """Return ``(protocol, packets, bytes)`` sorted by packet count."""
        with self.lock:
            counts: Dict[str, Dict[str, int]] = {}
            for packet in self.packets:
                name = packet.classify()
                entry = counts.setdefault(name, {"packets": 0, "bytes": 0})
                entry["packets"] += 1
                entry["bytes"] += packet.length
        return sorted(((name, data["packets"], data["bytes"]) for name, data in counts.items()),
                      key=lambda item: item[1], reverse=True)

    def rates(self) -> Tuple[float, float]:
        """Return the current ``(packets_per_second, bytes_per_second)``."""
        with self.lock:
            now = int(time.time())
            relevant = [(sec, packets, size) for sec, packets, size in self._bucket_pps
                        if sec >= now - self.window_seconds]
            if len(relevant) < 2:
                elapsed = max(time.time() - self.started, 0.5)
                return (self.total_packets / elapsed, self.total_bytes / elapsed)
            seconds = max(relevant[-1][0] - relevant[0][0], 1)
            packets = sum(item[1] for item in relevant)
            size = sum(item[2] for item in relevant)
            return (packets / seconds, size / seconds)

    def history(self, points: int = 60) -> List[float]:
        """Return a packets-per-second history suitable for a sparkline."""
        with self.lock:
            return [float(item[1]) for item in list(self._bucket_pps)[-points:]]

    def top_talkers(self, limit: int = 10) -> List[Tuple[str, int, int]]:
        """Return the busiest hosts as ``(address, packets, bytes)``."""
        with self.lock:
            rows = [(address, data.get("sent", 0) + data.get("received", 0),
                     data.get("bytes_out", 0)) for address, data in self.talkers.items()]
        return sorted(rows, key=lambda row: row[1], reverse=True)[:limit]

    def top_conversations(self, limit: int = 5) -> List[Tuple[str, int, int]]:
        """Return the busiest conversation pairs."""
        with self.lock:
            rows = [(key, data["packets"], data["bytes"]) for key, data in self.conversations.items()]
        return sorted(rows, key=lambda row: row[1], reverse=True)[:limit]

    def recent(self, limit: int = 12) -> List[Packet]:
        """Return the most recent packets, newest first."""
        with self.lock:
            return list(self.packets)[-limit:][::-1]


# --------------------------------------------------------------------------- #
# Capture backends
# --------------------------------------------------------------------------- #
class TSharkCapture:
    """Streams packet summaries out of tshark."""

    #: tshark fields we request; order matters when parsing
    FIELDS = ("frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
              "_ws.col.Protocol", "frame.len", "tcp.srcport", "tcp.dstport",
              "udp.srcport", "udp.dstport", "_ws.col.Info")

    def __init__(self, interface: Optional[str], stats: Stats, logger: Logger,
                 bpf: str = "", pcap_file: Optional[Path] = None) -> None:
        """Prepare a capture (started with :meth:`start`)."""
        self.interface = interface
        self.stats = stats
        self.logger = logger
        self.bpf = bpf
        self.pcap_file = pcap_file
        self.process: Optional[subprocess.Popen[str]] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False

    def command(self) -> List[str]:
        """Build the tshark argument vector."""
        tshark = deps.which("tshark") or "tshark"
        cmd = [tshark, "-l", "-n", "-T", "fields",
               "-E", "separator=|", "-E", "occurrence=f"]
        for field in self.FIELDS:
            cmd += ["-e", field]
        if self.pcap_file:
            cmd += ["-r", str(self.pcap_file)]
        else:
            cmd += ["-i", self.interface or "any"]
            if self.bpf:
                cmd += ["-f", self.bpf]
        return cmd

    def start(self) -> bool:
        """Launch tshark and the reader thread."""
        try:
            self.process = subprocess.Popen(  # noqa: S603 - fixed argv
                self.command(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error(f"could not start tshark: {exc}")
            return False
        self.running = True
        self.thread = threading.Thread(target=self._reader, name="tshark-reader", daemon=True)
        self.thread.start()
        self.logger.info(f"tshark capture started: {' '.join(self.command()[-6:])}")
        return True

    def _reader(self) -> None:
        """Parse tshark output until the process exits."""
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            if not self.running:
                break
            fields = line.rstrip("\n").split("|")
            if len(fields) < 7:
                continue
            try:
                timestamp = float(fields[0]) if fields[0] else time.time()
            except ValueError:
                timestamp = time.time()
            src = fields[1] or fields[3] or "?"
            dst = fields[2] or fields[4] or "?"
            protocol = fields[5] or "TCP"
            try:
                length = int(fields[6]) if fields[6] else 0
            except ValueError:
                length = 0
            sport = self._port(fields[7], fields[9])
            dport = self._port(fields[8], fields[10])
            info = fields[11] if len(fields) > 11 else ""
            self.stats.add(Packet(timestamp=timestamp, src=src, dst=dst, protocol=protocol,
                                  length=length, sport=sport, dport=dport, info=info))
        if self.running:
            stderr = ""
            try:
                stderr = (self.process.stderr.read() or "")[:400] if self.process.stderr else ""
            except (OSError, ValueError):
                pass
            if stderr:
                self.logger.warn(f"tshark exited: {stderr.strip()[:200]}")

    @staticmethod
    def _port(tcp: str, udp: str) -> Optional[int]:
        for value in (tcp, udp):
            if value:
                try:
                    return int(value)
                except ValueError:
                    continue
        return None

    def stop(self) -> None:
        """Terminate the capture."""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.process.kill()
                except OSError:
                    pass


class ScapyCapture:
    """Fallback capture path using scapy (requires root)."""

    def __init__(self, interface: Optional[str], stats: Stats, logger: Logger,
                 bpf: str = "", pcap_file: Optional[Path] = None) -> None:
        """Prepare a scapy-based capture."""
        self.interface = interface
        self.stats = stats
        self.logger = logger
        self.bpf = bpf
        self.pcap_file = pcap_file
        self.thread: Optional[threading.Thread] = None
        self.running = False

    def start(self) -> bool:
        """Start sniffing in a background thread."""
        try:
            import scapy.all as scapy  # type: ignore  # noqa: F401
        except ImportError:
            self.logger.error("scapy is not installed (pip install scapy)")
            return False
        try:
            import scapy.all as scapy  # type: ignore
        except ImportError:
            return False

        def handler(packet: Any) -> None:
            try:
                self.stats.add(self._convert(packet))
            except Exception:  # noqa: BLE001 - never break the sniffer
                pass

        def sniff() -> None:
            try:
                if self.pcap_file:
                    scapy.sniff(offline=str(self.pcap_file), prn=handler, store=False)
                else:
                    scapy.sniff(iface=self.interface, filter=self.bpf or None,
                                prn=handler, store=False)
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"scapy capture stopped: {exc}")

        self.running = True
        self.thread = threading.Thread(target=sniff, name="scapy-sniffer", daemon=True)
        self.thread.start()
        self.logger.info("scapy capture started (root + libpcap required)")
        return True

    @staticmethod
    def _convert(packet: Any) -> Packet:
        """Convert a scapy packet into our :class:`Packet` model."""
        import scapy.all as scapy  # type: ignore

        src = dst = "?"
        sport = dport = None
        protocol = "OTHER"
        if packet.haslayer(scapy.IP):
            src, dst = packet[scapy.IP].src, packet[scapy.IP].dst
        elif packet.haslayer(scapy.IPv6):
            src, dst = packet[scapy.IPv6].src, packet[scapy.IPv6].dst
        elif packet.haslayer(scapy.ARP):
            src = getattr(packet[scapy.ARP], "psrc", "?")
            dst = getattr(packet[scapy.ARP], "pdst", "?")
            protocol = "ARP"
        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            sport, dport = int(packet[scapy.TCP].sport), int(packet[scapy.TCP].dport)
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            sport, dport = int(packet[scapy.UDP].sport), int(packet[scapy.UDP].dport)
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"
        return Packet(timestamp=float(getattr(packet, "time", time.time())),
                      src=src, dst=dst, protocol=protocol, length=len(packet),
                      sport=sport, dport=dport,
                      info=packet.summary() if hasattr(packet, "summary") else "")

    def stop(self) -> None:
        """Stop the sniffer thread."""
        self.running = False


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def protocol_bar_chart(distribution: List[Tuple[str, int, int]], width: int = 30) -> List[str]:
    """Render a plain-text protocol bar chart."""
    if not distribution:
        return ["no packets captured yet"]
    top = distribution[:8]
    peak = max(entry[1] for entry in top) or 1
    total = sum(entry[1] for entry in distribution) or 1
    lines = []
    for name, packets, size in top:
        bar_length = max(1, int(width * packets / peak))
        percentage = 100.0 * packets / total
        bar = "█" * bar_length
        lines.append(f"  {name:<10} {bar:<{width}} {percentage:5.1f}%  "
                     f"{packets:>6} pkt  {human_bytes(size):>9}")
    return lines


def render_snapshot(stats: Stats) -> str:
    """Render a one-shot text snapshot of the current statistics."""
    pps, bps = stats.rates()
    distribution = stats.protocol_distribution()
    lines = [
        colour(f"  PACKET WEATHER  ::  {now_iso()}", C.BRIGHT_CYAN),
        f"  packets {stats.total_packets}  bytes {human_bytes(stats.total_bytes)}  "
        f"rate {pps:.1f} pkt/s  {human_bytes(bps)}/s",
        "",
        colour("  PROTOCOL MIX", C.BOLD),
    ]
    lines += protocol_bar_chart(distribution)
    lines.append("")
    lines.append(colour("  TOP TALKERS", C.BOLD))
    for address, packets, size in stats.top_talkers(8):
        lines.append(f"  {address:<20} {packets:>6} pkt  {human_bytes(size):>9}")
    lines.append("")
    lines.append(colour("  TOP CONVERSATIONS", C.BOLD))
    for conversation, packets, size in stats.top_conversations(5):
        lines.append(f"  {conversation:<42} {packets:>6} pkt  {human_bytes(size):>9}")
    lines.append("")
    lines.append(colour("  RECENT PACKETS", C.BOLD))
    for packet in stats.recent(10):
        lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(packet.timestamp))} "
                     f"{packet.src:<17} → {packet.dst:<17} {packet.classify():<9} {packet.length:>5}B")
    if stats.anomalies:
        lines.append("")
        lines.append(colour("  ANOMALIES", C.BRIGHT_YELLOW))
        for anomaly in list(stats.anomalies)[-5:]:
            lines.append(f"  ! {anomaly}")
    return "\n".join(lines)


def run_rich_ui(stats: Stats, refresh: float, interface: str, duration: Optional[float],
                logger: Logger, rotate: int = 300) -> int:
    """Run the rich live dashboard."""
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    def build_layout() -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="protocols", ratio=3),
            Layout(name="talkers", ratio=2),
        )
        return layout

    def header_panel() -> Panel:
        pps, bps = stats.rates()
        uptime = time.time() - stats.started
        text = Text()
        text.append("  PACKET WEATHER  ", style="bold cyan")
        text.append(f"iface={interface}   ", style="dim")
        text.append(f"{pps:,.1f} pkt/s", style="bold #00ffd5")
        text.append("   ")
        text.append(f"{human_bytes(bps)}/s", style="bold #8bd5ff")
        text.append("   ")
        text.append(f"total {stats.total_packets:,} pkt / {human_bytes(stats.total_bytes)}", style="dim")
        text.append(f"   window {int(uptime)}s", style="dim")
        return Panel(text, border_style="#5a6b7a")

    def protocol_panel() -> Panel:
        distribution = stats.protocol_distribution()
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column("proto", width=11)
        table.add_column("chart")
        table.add_column("pct", justify="right", width=7)
        table.add_column("packets", justify="right", width=9)
        table.add_column("bytes", justify="right", width=10)
        if not distribution:
            table.add_row(Text("waiting for packets...", style="dim"), "", "", "", "")
        total = sum(entry[1] for entry in distribution) or 1
        peak = max((entry[1] for entry in distribution), default=1) or 1
        for name, packets, size in distribution[:10]:
            bar_width = max(1, int(28 * packets / peak))
            bar = Text("█" * bar_width, style=PROTOCOL_COLOURS.get(name, "#8bd5ff"))
            table.add_row(
                Text(name, style="bold"),
                bar,
                Text(f"{100.0 * packets / total:5.1f}%", style="dim"),
                Text(f"{packets:,}", style="bold"),
                Text(human_bytes(size), style="dim"))
        history = stats.history(48)
        chart = Text()
        if history:
            chart.append("  packets/s trend: ")
            spark_chars = "▁▂▃▄▅▆▇█"
            peak_hist = max(history) or 1
            for value in history:
                index = min(len(spark_chars) - 1, int((value / peak_hist) * (len(spark_chars) - 1)))
                chart.append(spark_chars[index], style="#00ffd5")
        return Panel(Group(table, Text(""), chart), title="protocol distribution",
                     border_style="#5a6b7a")

    def talkers_panel() -> Panel:
        table = Table(expand=True, show_header=True, header_style="bold magenta", box=None)
        table.add_column("host", overflow="fold")
        table.add_column("pkts", justify="right")
        table.add_column("bytes", justify="right")
        for address, packets, size in stats.top_talkers(11):
            table.add_row(Text(address, style="#8bd5ff"), f"{packets:,}", human_bytes(size))
        if not stats.top_talkers(1):
            table.add_row(Text("no traffic yet", style="dim"), "", "")
        table.add_section()
        table.add_row(Text("top conversations", style="bold"), "", "")
        for conversation, packets, size in stats.top_conversations(4):
            table.add_row(Text(conversation[:34], style="dim"), f"{packets:,}", human_bytes(size))
        return Panel(table, title="top talkers", border_style="#5a6b7a")

    def footer_panel() -> Panel:
        recent = stats.recent(1)
        text = Text()
        if recent:
            packet = recent[0]
            text.append(f"  {time.strftime('%H:%M:%S', time.localtime(packet.timestamp))}  ",
                        style="dim")
            text.append(f"{packet.src} → {packet.dst}  ", style="#8bd5ff")
            text.append(f"{packet.classify()}  ", style="bold #00ffd5")
            text.append(f"{packet.length}B  ", style="dim")
            text.append(packet.info[:60], style="dim")
        if stats.anomalies:
            text.append("\n  ! ", style="bold yellow")
            text.append(list(stats.anomalies)[-1][:96], style="yellow")
        text.append("\n  q to quit · r to reset counters · passive capture only", style="dim")
        return Panel(text, border_style="#5a6b7a")

    layout = build_layout()
    layout["header"].update(header_panel())

    layout["footer"].update(footer_panel())
    layout["body"]["protocols"].update(protocol_panel())
    layout["body"]["talkers"].update(talkers_panel())

    deadline = time.time() + duration if duration else None
    with Live(layout, console=console, refresh_per_second=max(1, int(1 / refresh)),
              screen=True) as live:
        while True:
            if deadline and time.time() > deadline:
                break
            layout["header"].update(header_panel())
            layout["body"]["protocols"].update(protocol_panel())
            layout["body"]["talkers"].update(talkers_panel())
            layout["footer"].update(footer_panel())
            live.update(layout)
            time.sleep(refresh)
            if rotate and (time.time() - stats.started) > rotate:
                logger.info("rotating statistics window")
                stats.reset()
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="packet_weather.py",
        description="live packet capture visualisation (protocol mix, rates, top talkers)",
        epilog="Also available as: cdeck packets")
    parser.add_argument("interface", nargs="?", default=None,
                        help="interface to capture on (default: from cyberdeck.conf)")
    parser.add_argument("-i", "--interface", dest="interface_opt", default=None,
                        help="interface to capture on (explicit form)")
    parser.add_argument("--read", metavar="PCAP", help="replay a pcap/pcapng file instead of live capture")
    parser.add_argument("-f", "--filter", default=None, help="BPF capture filter (e.g. 'tcp port 443')")
    parser.add_argument("--refresh", type=float, default=None, help="display refresh interval in seconds")
    parser.add_argument("--duration", type=float, default=None, help="stop after N seconds (default: run until quit)")
    parser.add_argument("--window", type=int, default=None, help="rolling statistics window in seconds")
    parser.add_argument("--rotate", type=int, default=None, help="reset counters every N seconds (0 = never)")
    parser.add_argument("--once", action="store_true", help="print a snapshot after --duration and exit")
    parser.add_argument("--json", action="store_true", help="with --once/--json, emit JSON")
    parser.add_argument("--write-db", action="store_true",
                        help="record protocol totals into the shared events database")
    parser.add_argument("--version", action="version", version=f"packet_weather {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("packet_weather", str(config.get("general.log_level", "INFO")))

    interface = args.interface_opt or args.interface or str(
        config.get("capture.interface", "") or config.get("network.primary_interface", "any"))
    bpf = args.filter if args.filter is not None else str(config.get("capture.bpf_filter", ""))
    refresh = args.refresh or float(config.get("capture.refresh_interval", 1))
    window = args.window or int(config.get("capture.window_seconds", 60))
    rotate = args.rotate if args.rotate is not None else int(config.get("capture.rotation_seconds", 300))
    pcap = Path(args.read).expanduser() if args.read else None

    if pcap and not pcap.exists():
        logger.error(f"capture file not found: {pcap}")
        return 2

    stats = Stats(window_seconds=window)

    # ---- choose a backend ------------------------------------------------- #
    capture: Any = None
    if deps.have("tshark"):
        capture = TSharkCapture(interface, stats, logger, bpf, pcap)
        if not capture.start():
            logger.warn("tshark failed to start - trying scapy")
            capture = None
    if capture is None:
        if pcap:
            logger.error("reading pcap files requires tshark (pacman -S wireshark-cli)")
            return 3
        if not deps.have_module("scapy"):
            logger.error("neither tshark nor scapy is available - install wireshark-cli or scapy")
            return 3
        if os.geteuid() != 0:
            logger.error("live capture requires root: sudo cdeck packets")
            return 1
        capture = ScapyCapture(interface, stats, logger, bpf, pcap)
        if not capture.start():
            return 3

    exit_code = 0
    try:
        if pcap:
            # Give the replay a moment to finish, then always render once
            logger.info(f"replaying {pcap} (this will take a few seconds)")
            time.sleep(min(6.0, max(1.0, pcap.stat().st_size / 4_000_000)))
            print(render_snapshot(stats))
        elif args.once:
            duration = args.duration or 15.0
            logger.info(f"capturing for {duration:.0f}s before printing the snapshot")
            time.sleep(duration)
            if args.json:
                pps, bps = stats.rates()
                print(json.dumps({
                    "ts": now_iso(), "interface": interface,
                    "packets": stats.total_packets, "bytes": stats.total_bytes,
                    "pps": round(pps, 2), "bps": round(bps, 2),
                    "protocols": [{"name": n, "packets": p, "bytes": b}
                                  for n, p, b in stats.protocol_distribution()],
                    "talkers": [{"host": h, "packets": p, "bytes": b}
                                for h, p, b in stats.top_talkers(10)],
                    "conversations": [{"pair": c, "packets": p, "bytes": b}
                                      for c, p, b in stats.top_conversations(10)],
                    "anomalies": list(stats.anomalies),
                }, indent=2))
            else:
                print(render_snapshot(stats))
        else:
            try:
                import rich  # noqa: F401
                rich_available = True
            except ImportError:
                rich_available = False
            if rich_available:
                run_rich_ui(stats, refresh, interface or "auto", args.duration, logger, rotate)
            else:
                logger.warn("rich is not installed - falling back to a text loop")
                deadline = time.time() + args.duration if args.duration else None
                while not deadline or time.time() < deadline:
                    os.system("clear")  # noqa: S605 - deliberate terminal clear
                    print(render_snapshot(stats))
                    time.sleep(max(1.0, refresh * 2))
    except KeyboardInterrupt:
        logger.info("capture interrupted by operator")
    finally:
        capture.stop()
        if args.write_db and stats.total_packets:
            pps, bps = stats.rates()
            try:
                with Database("events", logger=logger) as db:
                    db.event("packet_weather", "capture",
                             f"captured {stats.total_packets} packets on {interface}",
                             "INFO",
                             {"packets": stats.total_packets, "bytes": stats.total_bytes,
                              "pps": round(pps, 2),
                              "protocols": {n: p for n, p, _ in stats.protocol_distribution()[:8]}})
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"could not record capture summary: {exc}")
        logger.info(f"capture closed ({stats.total_packets} packets, "
                    f"{human_bytes(stats.total_bytes)})")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
