#!/usr/bin/env python3
"""
gpio/oled_display.py - the deck's 128x64 status panel.
=======================================================

Description
-----------
Drives a small I2C OLED (SSD1306 or SH1106, 128x64 by default) as a heads-up
panel for the deck. Everything is drawn with the dependency-free driver and
built-in 5x7 font in ``lib/cybergpio.py``, so no extra Python packages are
needed - just the panel, an I2C bus, and the address from
``gpio.oled_i2c_address``.

Pages
-----
======= =====================================================================
status   host, address, VPN, service count, uptime - the default page
network  interface, MAC, gateway, DNS and wireless state
vitals   CPU load, memory, disk, battery, temperature with bar graphs
alerts   the newest alerts from the shared database, one per line
sdr      receiver presence and the last capture written
engage   active engagement directory and its report count
clock    big clock with a scrolling deck banner
splash   the theme's art, scaled to the panel
======= =====================================================================

Modes
-----
``--page NAME``     draw one page (default: ``status``)
``--all``           cycle through every page once
``--watch``         refresh continuously, rotating pages on a timer
``--text "..."``    draw four custom lines
``--alert-severity``  draw the alert badge for a severity (used by the LED hook)
``--contrast N``    set the panel contrast (0-255)

Without a panel the tool tells you why and draws into an in-memory buffer, which
is what the tests and ``--simulate`` use; ``--dump`` prints that buffer as ASCII
art so you can see exactly what would have appeared.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library, lib/cybergpio.py
              optional: a real SSD1306/SH1106 panel on /dev/i2c-*
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Usage
-----
    sudo ./oled_display.py --page status
    ./oled_display.py --all --simulate --dump
    ./oled_display.py --watch --pages status,vitals,alerts --interval 5
    ./oled_display.py --text "ENGAGEMENT ACTIVE" "10.0.0.0/24" "captures/wifi"
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "lib",
    Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")) / "lib",
]
for _candidate in _LIB_CANDIDATES:
    if (_candidate / "cybergpio.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

try:
    import cybergpio as gpio  # type: ignore
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cybergpio.py is not importable ({exc})\n")
    sys.exit(1)

try:
    from cyberlib import Config, Database, Hardware, now_iso  # type: ignore
except ImportError:  # pragma: no cover
    from cybergpio import Logger  # type: ignore

    Config = None  # type: ignore
    Database = None  # type: ignore
    Hardware = None  # type: ignore

    def now_iso() -> str:
        """Fallback timestamp helper.

        Returns:
            An ISO-8601 timestamp.
        """
        return datetime.now().astimezone().isoformat(timespec="seconds")

VERSION = "1.0.0"

#: Every page this tool can draw, in rotation order
PAGES = ("status", "network", "vitals", "alerts", "sdr", "engage", "clock", "splash")

#: A 5x7 page holds eight text rows on a 64-pixel panel
ROWS = 8

#: Simple progress-bar glyphs
BAR_FULL = "#"
BAR_EMPTY = "."


@dataclass
class Panel:
    """The rendering target: a real SSD1306 or the in-memory stand-in."""

    display: Any
    note: str
    width: int = 128
    height: int = 64
    simulated: bool = False

    @property
    def text_rows(self) -> int:
        """How many 8-pixel text rows the panel has.

        Returns:
            The row count.
        """
        return max(1, self.height // 8)

    def clear(self) -> None:
        """Blank the panel buffer."""
        self.display.clear()

    def text(self, row: int, message: str, scale: int = 1, x: int = 0,
             invert: bool = False) -> None:
        """Draw one line of text.

        Args:
            row: the text row (0 based).
            message: the text.
            scale: 1 or 2.
            x: left offset in pixels.
            invert: draw dark-on-light.
        """
        self.display.text(x, row if scale == 1 else row, message[:21 if scale == 1 else 10],
                          scale, invert)

    def flush(self) -> None:
        """Push the buffer to the panel."""
        self.display.display()

    def close(self) -> None:
        """Release the panel."""
        self.display.close()

    def ascii_art(self) -> str:
        """Render the buffer as ASCII art (page-major, 8 rows per page).

        Returns:
            A multi-line string, one character per pixel.
        """
        buffer = getattr(self.display, "buffer", b"")
        lines: List[str] = []
        for page in range(len(buffer) // self.width):
            block = buffer[page * self.width:(page + 1) * self.width]
            for bit in range(8):
                lines.append("".join("#" if byte & (1 << bit) else "."
                                     for byte in block))
        return "\n".join(lines)


class OledDisplay:
    """Draws the deck's pages onto the panel.

    Args:
        config: loaded cyberdeck configuration (or ``None``).
        logger: shared logger.
        simulate: force the in-memory panel.
        contrast: panel contrast (0-255) or ``None`` to leave it alone.
    """

    def __init__(self, config: Any = None, logger: Optional[Any] = None,
                 simulate: bool = False, contrast: Optional[int] = None) -> None:
        """Open the panel and prepare the page renderers."""
        self.config = config
        self.logger = logger or gpio.Logger("oled_display")
        self.install_dir = Path(str(self._get("general.install_dir",
                                              "/opt/cyberdeck-arsenal")))
        self.display, note = gpio.make_display(config, self.logger, simulate)
        self.panel = Panel(self.display, note,
                           width=getattr(self.display, "width", 128),
                           height=getattr(self.display, "height", 64),
                           simulated=isinstance(self.display, gpio.SSDDummy))
        self.ready = not isinstance(self.display, gpio.SSDDummy) or simulate
        if contrast is not None:
            try:
                self.display.command(gpio.SSD1306_SET_CONTRAST, int(contrast) & 0xFF)
            except Exception as exc:  # noqa: BLE001 - only a real panel has commands
                self.logger.debug("contrast not applied: %s", exc)
        self.pages: Dict[str, Callable[[], None]] = {
            "status": self.page_status,
            "network": self.page_network,
            "vitals": self.page_vitals,
            "alerts": self.page_alerts,
            "sdr": self.page_sdr,
            "engage": self.page_engage,
            "clock": self.page_clock,
            "splash": self.page_splash,
        }
        self.ticker = 0
        self.running = True

    # -- configuration ------------------------------------------------------ #
    def _get(self, dotted: str, default: Any = None) -> Any:
        """Read a configuration value safely.

        Args:
            dotted: the ``section.key`` path.
            default: the fallback.

        Returns:
            The configured value or the default.
        """
        if self.config is None:
            return default
        try:
            value = self.config.get(dotted, default)
        except Exception:  # noqa: BLE001
            return default
        return default if value is None else value

    # -- drawing helpers ---------------------------------------------------- #
    def header(self, title: str, suffix: str = "") -> None:
        """Draw the inverted title bar.

        Args:
            title: the page name.
            suffix: right-aligned text (usually the time).
        """
        text = title.upper()[:14]
        right = suffix or datetime.now().strftime("%H:%M")
        line = f"{text:<14}{right:>7}"
        self.panel.text(0, line[:21], invert=True)

    def draw(self, page: str) -> None:
        """Render a page by name and flush it.

        Args:
            page: a key of :attr:`pages`.
        """
        renderer = self.pages.get(page)
        if renderer is None:
            self.logger.error("unknown page '%s' (known: %s)", page, ", ".join(self.pages))
            return
        self.panel.clear()
        try:
            renderer()
        except Exception as exc:  # noqa: BLE001 - a bad probe must not blank the panel
            self.logger.debug("page %s failed: %s", page, exc)
            self.panel.text(1, "PAGE ERROR")
            self.panel.text(3, str(exc)[:21])
        self.panel.flush()

    def rotate(self, pages: Sequence[str], interval: float) -> None:
        """Cycle through the given pages until stopped.

        Args:
            pages: the page names to rotate.
            interval: seconds per page.
        """
        index = 0
        last = 0.0
        while self.running:
            now = time.time()
            if now - last >= interval:
                self.draw(pages[index % len(pages)])
                index += 1
                last = now
            time.sleep(0.1)

    # -- probes ------------------------------------------------------------- #
    def hostname(self) -> str:
        """Return a short hostname.

        Returns:
            The hostname, truncated to 16 characters.
        """
        return (os.uname().nodename if hasattr(os, "uname") else "deck")[:16]

    def address(self) -> Tuple[str, str]:
        """Return the primary interface and its address.

        Returns:
            A ``(interface, address)`` pair.
        """
        try:
            result = subprocess.run(["ip", "-o", "route", "show", "default"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=4, check=False)
            fields = result.stdout.decode(errors="replace").split()
            interface = fields[fields.index("dev") + 1] if "dev" in fields else ""
            detail = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", interface],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=4, check=False)
            parts = detail.stdout.decode(errors="replace").split()
            address = parts[parts.index("inet") + 1] if "inet" in parts else "no address"
            return interface, address.split("/")[0]
        except (OSError, subprocess.TimeoutExpired, ValueError):  # pragma: no cover
            return "", "unknown"

    def uptime_text(self) -> str:
        """Return a short uptime string.

        Returns:
            Uptime such as ``3d04h`` or ``unknown``.
        """
        try:
            seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError, IndexError):
            return "unknown"
        days, rest = divmod(seconds, 86400)
        hours, rest = divmod(rest, 3600)
        minutes = rest // 60
        if days:
            return f"{days}d{hours:02d}h"
        if hours:
            return f"{hours}h{minutes:02d}m"
        return f"{minutes}m"

    def load(self) -> Tuple[float, float, float]:
        """Return the load averages.

        Returns:
            The 1, 5 and 15 minute load averages.
        """
        try:
            return os.getloadavg()
        except (OSError, AttributeError):  # pragma: no cover
            return 0.0, 0.0, 0.0

    def memory_percent(self) -> float:
        """Return the used memory percentage.

        Returns:
            The percentage used, or 0.0 when it cannot be read.
        """
        path = Path("/proc/meminfo")
        values: Dict[str, int] = {}
        try:
            for line in path.read_text().splitlines():
                key, _, rest = line.partition(":")
                parts = rest.strip().split()
                if parts:
                    values[key] = int(parts[0])
        except (OSError, ValueError):
            return 0.0
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", values.get("MemFree", 0))
        if not total:
            return 0.0
        return round((total - available) / total * 100, 1)

    def disk_percent(self) -> float:
        """Return the disk usage percentage for the install directory.

        Returns:
            The percentage used.
        """
        try:
            import shutil
            usage = shutil.disk_usage(self.install_dir if self.install_dir.exists()
                                      else Path("/"))
        except OSError:
            return 0.0
        return round((usage.total - usage.free) / usage.total * 100, 1)

    def battery(self) -> Tuple[Optional[int], str]:
        """Return the battery percentage and status.

        Returns:
            A ``(percent, status)`` pair; percent is ``None`` when absent.
        """
        for entry in sorted(Path("/sys/class/power_supply").glob("BAT*")):
            capacity = entry / "capacity"
            if not capacity.is_file():
                continue
            try:
                percent = int(capacity.read_text().strip())
            except (OSError, ValueError):
                continue
            status = ""
            status_file = entry / "status"
            if status_file.is_file():
                try:
                    status = status_file.read_text().strip()
                except OSError:
                    status = ""
            return percent, status
        return None, ""

    def temperature(self) -> Optional[float]:
        """Return the hottest thermal zone temperature.

        Returns:
            The temperature in Celsius, or ``None``.
        """
        hottest: Optional[float] = None
        for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp")):
            try:
                value = float(zone.read_text().strip())
            except (OSError, ValueError):
                continue
            celsius = value / 1000.0 if value > 1000 else value
            if hottest is None or celsius > hottest:
                hottest = celsius
        return None if hottest is None else round(hottest, 1)

    def vpn_state(self) -> str:
        """Return a one-word VPN state.

        Returns:
            ``wireguard``, ``openvpn``, ``tor`` or ``off``.
        """
        def running(name: str) -> bool:
            for entry in Path("/proc").iterdir() if Path("/proc").is_dir() else []:
                if not entry.name.isdigit():
                    continue
                try:
                    comm = (entry / "comm").read_text().strip()
                except OSError:
                    continue
                if comm == name[:15]:
                    return True
            return False

        if running("openvpn"):
            return "openvpn"
        if running("tor"):
            return "tor"
        try:
            result = subprocess.run(["ip", "link", "show", "type", "wireguard"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=4, check=False)
            if b"wg" in result.stdout:
                return "wireguard"
        except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
            pass
        return "off"

    def service_count(self) -> Tuple[int, int]:
        """Count the running cyberdeck units.

        Returns:
            An ``(active, installed)`` pair.
        """
        units = ("cyberdeck-monitor.service", "probe-logger.service",
                 "ble-scanner.service", "rogue-ap-detector.service",
                 "usb-watcher.service", "mac-rotator.timer")
        active = installed = 0
        for unit in units:
            try:
                result = subprocess.run(["systemctl", "is-active", unit],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=4, check=False)
            except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
                return 0, 0
            state = result.stdout.decode(errors="replace").strip()
            if state:
                installed += 1
                if state == "active":
                    active += 1
        return active, installed

    def recent_alerts(self, limit: int = 4) -> List[Tuple[str, str, str]]:
        """Read the newest alerts from the shared database.

        Args:
            limit: how many alerts to return.

        Returns:
            A list of ``(timestamp, severity, message)`` tuples.
        """
        path = self.install_dir / "data" / "events.db"
        if not path.is_file():
            return []
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                rows = connection.execute(
                    "SELECT ts, severity, message FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,)).fetchall()
        except sqlite3.Error:
            return []
        return [(str(row[0] or "")[:16], str(row[1] or ""), str(row[2] or ""))
                for row in rows]

    def sdr_devices(self) -> List[str]:
        """List the SDR receivers attached to the host.

        Returns:
            A list of receiver names.
        """
        found: List[str] = []
        try:
            result = subprocess.run(["lsusb"], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=4, check=False)
            listing = result.stdout.decode(errors="replace").lower()
            if "hackrf" in listing or "great scott" in listing:
                found.append("hackrf")
            if "rtl2838" in listing or "rtl2832" in listing or "realtek" in listing:
                found.append("rtl-sdr")
        except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
            pass
        if Path("/dev/ttyACM0").exists():
            found.append("serial")
        return found

    def last_capture(self) -> str:
        """Return the newest capture file name.

        Returns:
            The file name, or ``none yet``.
        """
        root = self.install_dir / "captures"
        if not root.is_dir():
            return "none yet"
        newest: Optional[Path] = None
        newest_time = 0.0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                stamp = path.stat().st_mtime
            except OSError:
                continue
            if stamp > newest_time:
                newest, newest_time = path, stamp
        if newest is None:
            return "none yet"
        return newest.name[:21]

    def engagement(self) -> Tuple[str, int]:
        """Return the newest engagement directory and its report count.

        Returns:
            A ``(name, reports)`` pair.
        """
        root = self.install_dir / "reports"
        if not root.is_dir():
            return "none", 0
        directories = sorted((path for path in root.iterdir() if path.is_dir()),
                             key=lambda path: path.stat().st_mtime, reverse=True)
        if not directories:
            return "none", 0
        newest = directories[0]
        reports = len(list(newest.glob("*.md"))) + len(list(newest.glob("*.html")))
        return newest.name[:21], reports

    # -- pages -------------------------------------------------------------- #
    def page_status(self) -> None:
        """Draw the summary page."""
        self.header("status")
        interface, address = self.address()
        active, installed = self.service_count()
        rows = [
            (self.hostname(), True),
            (f"{interface or 'no link'} {address}"[:21], False),
            (f"vpn {self.vpn_state()}  up {self.uptime_text()}"[:21], False),
            (f"services {active}/{installed}"[:21], False),
            (f"alerts {len(self.recent_alerts(8))}"[:21], False),
        ]
        for index, (text, invert) in enumerate(rows, start=1):
            self.panel.text(index, text, invert=invert)

    def page_network(self) -> None:
        """Draw the network page."""
        self.header("network")
        interface, address = self.address()
        mac = "unknown"
        try:
            mac = Path(f"/sys/class/net/{interface}/address").read_text().strip()
        except (OSError, ValueError):
            pass
        wireless = ""
        try:
            result = subprocess.run(["iwgetid", "-r", interface], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=4, check=False)
            wireless = result.stdout.decode(errors="replace").strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        rows = [
            f"if {interface or 'none'}",
            f"ip {address}",
            f"mac {mac}"[:21],
            f"vpn {self.vpn_state()}",
            (f"ssid {wireless}" if wireless else "ssid -")[:21],
        ]
        for index, text in enumerate(rows, start=1):
            self.panel.text(index, text)
        self.panel.text(6, f"mon {self.monitor_interface() or '-'}"[:21])

    def monitor_interface(self) -> str:
        """Return the configured monitor-mode interface.

        Returns:
            The interface name, or an empty string.
        """
        value = str(self._get("network.monitor_interface", "") or "")
        return value if value and Path(f"/sys/class/net/{value}").exists() else ""

    def bar(self, percent: float, width: int = 10) -> str:
        """Render a text progress bar.

        Args:
            percent: the value from 0 to 100.
            width: bar width in characters.

        Returns:
            The bar.
        """
        filled = max(0, min(width, int(round(percent / 100 * width))))
        return "[" + (BAR_FULL * filled) + (BAR_EMPTY * (width - filled)) + "]"

    def page_vitals(self) -> None:
        """Draw the vitals page with bars."""
        self.header("vitals")
        load = self.load()[0]
        cores = os.cpu_count() or 1
        load_percent = min(100.0, load / cores * 100)
        memory = self.memory_percent()
        disk = self.disk_percent()
        battery, battery_status = self.battery()
        temperature = self.temperature()
        self.panel.text(1, f"cpu {load_percent:5.1f}% {self.bar(load_percent)}")
        self.panel.text(2, f"mem {memory:5.1f}% {self.bar(memory)}")
        self.panel.text(3, f"dsk {disk:5.1f}% {self.bar(disk)}")
        if battery is None:
            self.panel.text(4, "battery -")
        else:
            self.panel.text(4, f"bat {battery:3d}% {self.bar(float(battery))} "
                               f"{battery_status[:4]}")
        if temperature is None:
            self.panel.text(5, "temp -")
        else:
            self.panel.text(5, f"temp {temperature:.1f}C")
        self.panel.text(6, f"load {load:.2f} of {cores} cores")

    def page_alerts(self) -> None:
        """Draw the alert feed page."""
        self.header("alerts")
        alerts = self.recent_alerts(5)
        if not alerts:
            self.panel.text(2, "no alerts")
            self.panel.text(4, "the deck is quiet")
            return
        for index, (stamp, severity, message) in enumerate(alerts, start=1):
            if index >= ROWS:
                break
            line = f"{severity[:4]:<4}{message}"[:21]
            self.panel.text(index, line, invert=severity.upper() in ("CRITICAL", "ALERT", "ERROR"))

    def page_sdr(self) -> None:
        """Draw the SDR page."""
        self.header("sdr")
        devices = self.sdr_devices()
        enabled = bool(self._get("sdr.enabled", True))
        rows = [
            f"radio {', '.join(devices) if devices else 'none'}"[:21],
            f"scanner {'enabled' if enabled else 'disabled'}",
            f"gain {self._get('sdr.gain', 'auto')}",
            f"rate {self._get('sdr.sample_rate', 2048000)}",
        ]
        for index, text in enumerate(rows, start=1):
            self.panel.text(index, text)
        self.panel.text(6, f"last {self.last_capture()}"[:21])

    def page_engage(self) -> None:
        """Draw the engagement page."""
        self.header("engage")
        name, reports = self.engagement()
        rows = [
            f"engagement {name}"[:21],
            f"reports {reports}",
            f"captures {self.capture_count()}",
        ]
        for index, text in enumerate(rows, start=2):
            self.panel.text(index, text)
        self.panel.text(5, "authorised use only")
        self.panel.text(6, "docs/LEGAL.md")

    def capture_count(self) -> int:
        """Count the files under the captures directory.

        Returns:
            The number of captured files.
        """
        root = self.install_dir / "captures"
        if not root.is_dir():
            return 0
        return sum(1 for path in root.rglob("*") if path.is_file())

    def page_clock(self) -> None:
        """Draw the clock page."""
        self.panel.clear()
        now = datetime.now()
        time_text = now.strftime("%H:%M")
        date_text = now.strftime("%a %d %b %Y")
        self.panel.text(0, time_text, scale=2)
        self.panel.text(2, date_text)
        self.ticker += 1
        banner = f"cyberdeck {VERSION} · {str(self._get('display.theme', 'cyberpunk'))}"
        width = 21
        window = (banner + "   ") * 2
        offset = self.ticker % len(banner)
        self.panel.text(4, window[offset:offset + width])
        self.panel.text(6, f"up {self.uptime_text()}"[:21])

    def page_splash(self) -> None:
        """Draw the theme splash (art scaled, or a large deck mark)."""
        theme = str(self._get("display.theme", "cyberpunk"))
        art = self.read_theme_art(theme)
        self.panel.clear()
        if art:
            lines = [line.rstrip() for line in art.strip("\n").splitlines() if line.strip()]
            # Centre the art: the panel is 21 characters wide, 8 rows tall
            for index, line in enumerate(lines[: self.panel.text_rows]):
                self.panel.text(index, line[:21])
        else:
            self.panel.text(1, "CYBERDECK", invert=True)
            self.panel.text(3, "ARSENAL")
            self.panel.text(5, theme[:21])
        self.panel.text(self.panel.text_rows - 1, f"v{VERSION} · {theme}"[:21])

    def read_theme_art(self, theme: str) -> str:
        """Read a theme's splash art.

        Args:
            theme: the theme name.

        Returns:
            The art, or an empty string.
        """
        candidates = [
            Path(__file__).resolve().parent.parent / "aesthetic" / "themes" / f"{theme}.theme",
            self.install_dir / "aesthetic" / "themes" / f"{theme}.theme",
        ]
        for path in candidates:
            if not path.is_file():
                continue
            try:
                text = path.read_text()
            except OSError:
                continue
            match = None
            for line in text.splitlines():
                if line.strip().startswith("THEME_SPLASH_ART="):
                    match = line.split("=", 1)[1].strip()
                    break
            if match is None:
                continue
            art = match.strip("'\"")
            if art.strip():
                return art
        return ""

    # -- misc --------------------------------------------------------------- #
    def alert_badge(self, severity: str) -> None:
        """Draw the alert badge used by the LED/alert integration.

        Args:
            severity: the alert severity.
        """
        self.panel.clear()
        badge = {"CRITICAL": "!! CRITICAL !!", "ALERT": "!! ALERT !!",
                 "ERROR": "!! ERROR !!", "HIGH": "! HIGH !"}.get(
                     severity.upper(), f"[{severity.upper()}]")
        self.panel.text(2, badge[:21], scale=1, invert=True)
        self.panel.text(4, datetime.now().strftime("%H:%M:%S"))
        self.panel.text(5, "see cdeck status")
        self.panel.flush()

    def text_page(self, lines: Sequence[str]) -> None:
        """Draw up to eight custom lines.

        Args:
            lines: the lines to draw.
        """
        self.panel.clear()
        for index, line in enumerate(list(lines)[: self.panel.text_rows]):
            self.panel.text(index, line[:21])
        self.panel.flush()

    def status(self) -> Dict[str, Any]:
        """Build the display status.

        Returns:
            A dictionary describing the panel.
        """
        return {
            "version": VERSION,
            "panel_note": self.panel.note,
            "simulated": self.panel.simulated,
            "width": self.panel.width,
            "height": self.panel.height,
            "pages": list(self.pages),
            "theme": str(self._get("display.theme", "cyberpunk")),
            "address": "0x%02X" % int(self._get("gpio.oled_i2c_address", "0x3C").replace("0x", ""),
                                      16) if self._get("gpio.oled_i2c_address") else "0x3C",
        }

    def close(self) -> None:
        """Release the panel."""
        try:
            self.panel.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="oled_display.py",
        description="128x64 OLED status panel for the cyberdeck",
        epilog="authorised use only - see docs/LEGAL.md")
    parser.add_argument("--version", action="version", version=f"oled_display {VERSION}")
    parser.add_argument("--page", default="status", help=f"page to draw ({', '.join(PAGES)})")
    parser.add_argument("--all", action="store_true", help="draw every page once")
    parser.add_argument("--watch", action="store_true", help="keep refreshing the page")
    parser.add_argument("--pages", default="", help="comma-separated pages for --watch")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="seconds per page when rotating (default: 5)")
    parser.add_argument("--text", nargs="*", default=None, help="draw custom lines")
    parser.add_argument("--alert-severity", default="",
                        help="draw the alert badge for this severity and exit")
    parser.add_argument("--contrast", type=int, default=None, help="panel contrast 0-255")
    parser.add_argument("--addr", default=None, help="I2C address, e.g. 0x3D")
    parser.add_argument("--simulate", action="store_true", help="use the in-memory panel")
    parser.add_argument("--dump", action="store_true",
                        help="print the panel buffer as ASCII art")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", "-q", action="store_true", help="silence the console log")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the OLED display tool.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    config = None
    level = "INFO"
    if Config is not None:
        try:
            config = Config().load()
            level = str(config.get("general.log_level", "INFO"))
        except Exception:  # noqa: BLE001
            config = None
    if args.addr and config is not None:
        try:
            config.set("gpio.oled_i2c_address", args.addr)
        except Exception:  # noqa: BLE001
            pass

    logger = gpio.Logger("oled_display", level, quiet=args.quiet or args.json)
    if not (args.quiet or args.json):
        logger.banner("OLED display", f"v{VERSION} · 128x64 status panel")

    display = OledDisplay(config, logger, simulate=args.simulate, contrast=args.contrast)
    logger.info("display: %s", display.panel.note)
    if display.panel.simulated and not args.simulate and not args.quiet:
        logger.warn("no panel detected - drawing into memory (use --dump to see it)")

    exit_code = 0
    try:
        if args.alert_severity:
            display.alert_badge(args.alert_severity)
        elif args.text is not None:
            display.text_page(args.text)
        elif args.all:
            for page in PAGES:
                display.draw(page)
                if args.dump:
                    print(f"--- {page} ---")
                    print(display.panel.ascii_art())
        else:
            pages = [page.strip() for page in args.pages.split(",") if page.strip()] \
                or [args.page]
            for page in pages:
                if page not in PAGES:
                    logger.error("unknown page '%s' (known: %s)", page, ", ".join(PAGES))
                    return 2
            if args.watch:
                def stop(_signum: int, _frame: Any) -> None:
                    logger.info("stopping the OLED rotation")
                    display.running = False

                for signal_name in ("SIGINT", "SIGTERM"):
                    try:
                        signal.signal(getattr(signal, signal_name), stop)
                    except (ValueError, OSError):  # pragma: no cover
                        pass
                display.rotate(pages, args.interval)
            else:
                display.draw(pages[0])

        if args.json:
            payload = {"status": display.status(),
                       "page": args.page if not args.all else "all"}
            if args.dump:
                payload["buffer"] = display.panel.ascii_art()
            print(json.dumps(payload, indent=2))
        elif args.dump:
            print(display.panel.ascii_art())
    finally:
        display.close()
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
