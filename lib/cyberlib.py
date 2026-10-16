#!/usr/bin/env python3
"""
cyberlib - shared runtime library for cyberdeck-arsenal
=======================================================

Description
-----------
Single import surface used by every Python component of cyberdeck-arsenal
(dashboards, recon modules, SDR tools, automation engine, GPIO helpers).

It centralises the concerns that must behave identically everywhere:

    * configuration loading (YAML, with sane defaults + dotted-key access)
    * logging to /var/log/cyberdeck-arsenal and the console, with colours
    * dependency / hardware probing with graceful degradation
    * SQLite database management (shared schema, WAL mode, WAL checkpointing)
    * OUI (MAC vendor) lookups from the local database
    * alert dispatch (terminal, notify-send, webhook, LED hook, DB feed)
    * legal authorisation gating
    * subprocess helpers that never hang a dashboard

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: stdlib only. Optional: PyYAML, psutil, requests, rich, netifaces
Licence     : MIT (see LICENSE)

Usage
-----
    from cyberlib import Config, Logger, Alerts, Hardware, Database, deps

    log = Logger("my_module")
    cfg = Config().load()
    if not deps.have("tshark"):
        log.warn("tshark missing - skipping")
"""

from __future__ import annotations

import csv
import json
import logging
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

INSTALL_DIR = Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal"))

#: Environment variables that override individual configuration keys
_ENV_OVERRIDES: Dict[str, str] = {
    "general.install_dir": "CYBERDECK_INSTALL_DIR",
    "general.log_level": "CYBERDECK_LOG_LEVEL",
}
REPO_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = INSTALL_DIR / "data"
LOG_DIR = INSTALL_DIR / "logs"
CAPTURE_DIR = INSTALL_DIR / "captures"
REPORT_DIR = INSTALL_DIR / "reports"
PROFILE_DIR = INSTALL_DIR / "profiles"
VAULT_DIR = INSTALL_DIR / "vault"
STATE_DIR = INSTALL_DIR / "state"

CONFIG_SEARCH: Tuple[Path, ...] = (
    Path(os.environ.get("CYBERDECK_CONF", "")) if os.environ.get("CYBERDECK_CONF") else INSTALL_DIR / "cyberdeck.conf",
    Path("/etc/cyberdeck-arsenal/cyberdeck.conf"),
    INSTALL_DIR / "config" / "cyberdeck.conf",
    REPO_DIR / "config" / "cyberdeck.conf",
)


def ensure_dirs() -> None:
    """Create the runtime directory tree if a component is run before setup.sh."""
    for directory in (INSTALL_DIR, DATA_DIR, LOG_DIR, CAPTURE_DIR, REPORT_DIR,
                      PROFILE_DIR, VAULT_DIR, STATE_DIR):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            # Fall back to a user-writable tree so non-root modules still work.
            alt = Path.home() / ".cyberdeck-arsenal" / directory.name
            alt.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Colours
# --------------------------------------------------------------------------- #

class C:
    """ANSI colour helpers. Disabled automatically when not a TTY."""

    enabled: bool = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = (
        "\033[30m", "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[37m")
    BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN, BRIGHT_MAGENTA = (
        "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[95m")
    BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"

    @classmethod
    def wrap(cls, text: str, *codes: str) -> str:
        """Wrap *text* in ANSI *codes* when colour output is enabled."""
        if not cls.enabled or not codes:
            return text
        return "".join(codes) + text + cls.RESET


def colour(text: str, colour_code: str) -> str:
    """Colourise *text* with a single ANSI escape."""
    return C.wrap(text, colour_code)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

class Logger:
    """Console + file logger used by every cyberdeck component.

    Writes to ``<install>/logs/<component>.log`` (falling back to
    ``~/.cyberdeck-arsenal/logs``) and to stderr/stdout depending on level.
    """

    _LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "WARN": 30,
               "ERROR": 40, "CRITICAL": 50}

    def __init__(self, component: str, level: str = "INFO", colour_output: bool = True,
                 log_dir: Optional[Path] = None, quiet: bool = False) -> None:
        """Create a logger for *component*."""
        self.component = component
        self.level_name = level.upper()
        self.level = self._LEVELS.get(self.level_name, 20)
        self.quiet = quiet
        self.colour_output = colour_output
        C.enabled = C.enabled and colour_output

        directory = log_dir or LOG_DIR
        try:
            directory.mkdir(parents=True, exist_ok=True)
            self.logfile: Optional[Path] = directory / f"{component}.log"
        except (PermissionError, OSError):
            fallback = Path.home() / ".cyberdeck-arsenal" / "logs"
            fallback.mkdir(parents=True, exist_ok=True)
            self.logfile = fallback / f"{component}.log"

        self._py = logging.getLogger(f"cyberdeck.{component}")
        self._py.setLevel(logging.DEBUG)
        if self.logfile and not self._py.handlers:
            try:
                handler = logging.FileHandler(self.logfile)
                handler.setFormatter(logging.Formatter(
                    "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"))
                self._py.addHandler(handler)
            except OSError:
                self.logfile = None
        self._py.propagate = False

    # -- internal ----------------------------------------------------------- #
    def _emit(self, level: str, message: str, code: str, symbol: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        plain = f"{stamp} {symbol} [{self.component}] {message}"
        if not self.quiet:
            print(C.wrap(plain, code))
        if self._py.handlers and self._LEVELS.get(level, 20) >= self.level:
            self._py.log(self._LEVELS[level], message)

    # -- public API --------------------------------------------------------- #
    @staticmethod
    def _format(message: str, args: Sequence[Any]) -> str:
        """Apply printf-style formatting when extra arguments are supplied.

        Callers may pass either a finished string or a printf-style template
        plus arguments (``logger.info("parsed %d hosts", count)``). A template
        without arguments is left untouched, so messages containing a literal
        percent sign cannot raise.
        """
        if not args:
            return message
        try:
            return message % args
        except (TypeError, ValueError):
            return " ".join(str(item) for item in (message, *args))

    def debug(self, message: str, *args: Any) -> None:
        """Log a debug message (file only unless level=DEBUG)."""
        message = self._format(message, args)
        if self._LEVELS["DEBUG"] >= self.level:
            self._emit("DEBUG", message, C.DIM, "·")
        elif self._py.handlers:
            self._py.debug(message)

    def info(self, message: str, *args: Any) -> None:
        """Log an informational message."""
        message = self._format(message, args)
        if self._LEVELS["INFO"] >= self.level:
            self._emit("INFO", message, C.BRIGHT_CYAN, "→")
        elif self._py.handlers:
            self._py.info(message)

    def ok(self, message: str, *args: Any) -> None:
        """Log a success message."""
        message = self._format(message, args)
        self._emit("INFO", message, C.BRIGHT_GREEN, "✔")

    def warn(self, message: str, *args: Any) -> None:
        """Log a warning."""
        message = self._format(message, args)
        if self._LEVELS["WARNING"] >= self.level:
            self._emit("WARNING", message, C.BRIGHT_YELLOW, "!")
        elif self._py.handlers:
            self._py.warning(message)

    def warning(self, message: str, *args: Any) -> None:
        """Alias for :meth:`warn` (matches the stdlib logging spelling)."""
        self.warn(message, *args)

    def success(self, message: str, *args: Any) -> None:
        """Alias for :meth:`ok` (matches common progress-logger spelling)."""
        self.ok(message, *args)

    def error(self, message: str, *args: Any) -> None:
        """Log an error."""
        message = self._format(message, args)
        self._emit("ERROR", message, C.BRIGHT_RED, "✘")

    def critical(self, message: str, *args: Any) -> None:
        """Log a critical error."""
        message = self._format(message, args)
        self._emit("CRITICAL", message, C.BRIGHT_RED + C.BOLD, "†")

    def alert(self, message: str, *args: Any) -> None:
        """Log an alert-feed worthy message."""
        message = self._format(message, args)
        self._emit("WARNING", message, C.BRIGHT_MAGENTA + C.BOLD, "⚠")

    def banner(self, title: str, subtitle: str = "") -> None:
        """Print a framed banner."""
        width = max(len(title), len(subtitle)) + 4
        line = "═" * width
        print(C.wrap(f"╔{line}╗", C.CYAN))
        print(C.wrap("║", C.CYAN) + f"  {C.wrap(title, C.BOLD)}" + " " * (width - len(title) - 1)
              + C.wrap("║", C.CYAN))
        if subtitle:
            print(C.wrap("║", C.CYAN) + f"  {C.wrap(subtitle, C.DIM)}"
                  + " " * (width - len(subtitle) - 1) + C.wrap("║", C.CYAN))
        print(C.wrap(f"╚{line}╝", C.CYAN))

    def tail(self, path: Path, lines: int = 10) -> List[str]:
        """Return the last *lines* of *path* (best effort, never raises)."""
        try:
            with open(path, "r", errors="replace") as handle:
                return handle.readlines()[-lines:]
        except OSError:
            return []


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "install_dir": str(INSTALL_DIR),
        "log_level": "INFO",
        "color_output": True,
        "authorised_use_acknowledged": False,
        "operator_name": "operator",
    },
    "network": {
        "primary_interface": "wlan0",
        "monitor_interface": "wlan1",
        "ethernet_interface": "eth0",
        "default_vpn_config": "/etc/openvpn/client.conf",
        "tor_enabled": False,
        "dns_servers": ["1.1.1.1", "9.9.9.9"],
        "kill_switch": True,
    },
    "monitoring": {
        "ble_scan_interval": 30,
        "probe_log_enabled": True,
        "arp_monitor_enabled": True,
        "rogue_ap_check_interval": 300,
        "service_watch_enabled": True,
        "hud_refresh_rate": 2,
    },
    "mac_rotation": {
        "enabled": True,
        "interval": 3600,
        "vendor_prefix": "random",
        "interfaces": ["wlan0"],
    },
    "api_keys": {
        "abuseipdb": "",
        "alienvault_otx": "",
        "greynoise": "",
        "shodan": "",
    },
    "alerts": {
        "new_device_alert": True,
        "rogue_ap_alert": True,
        "usb_insert_alert": True,
        "webhook_url": "",
        "desktop_notifications": True,
        "min_severity": "INFO",
    },
    "automation": {
        "auto_recon_on_connect": True,
        "auto_hash_usb": True,
        "low_battery_exfil": False,
        "battery_threshold": 15,
        "exfil_destination": "",
    },
    "scanning": {
        "default_depth": "standard",
        "output_dir": str(REPORT_DIR),
        "nmap_timing": "T4",
        "max_parallel_jobs": 4,
    },
    "sdr": {
        "enabled": True,
        "device_index": 0,
        "gain": "auto",
        "sample_rate": 2048000,
    },
    "gps": {
        "enabled": False,
        "device": "/dev/ttyACM0",
        "baud": 9600,
    },
    "gpio": {
        "enabled": False,
        "status_led_pin": 17,
        "alert_led_pin": 27,
        "button_pin": 22,
        "oled_enabled": False,
        "oled_i2c_address": "0x3C",
    },
    "display": {
        "theme": "cyberpunk",
        "hud_refresh_rate": 2,
        "show_gps": False,
        "show_sdr": True,
        "compact": False,
    },
    "vault": {
        "path": str(VAULT_DIR),
        "gpg_recipient": "",
        "auto_lock_minutes": 15,
    },
}


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict."""
    result: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(result[key], value)  # type: ignore[arg-type]
        else:
            result[key] = value
    return result


class Config:
    """Loads ``cyberdeck.conf`` (YAML) with defaults and dotted-key access."""

    def __init__(self, path: Optional[Path] = None) -> None:
        """Load the configuration from *path* (or from the standard locations)."""
        #: Explicit path passed to the constructor (winning over the defaults)
        self.path: Optional[Path] = Path(path) if path else None
        #: The merged configuration tree (defaults overlaid with the file)
        self.data: Dict[str, Any] = {}
        #: The file the configuration was read from
        self.loaded_from: Optional[Path] = None
        #: Keys changed through :meth:`set` and not yet written to disk
        self.dirty: Dict[str, Any] = {}

    def _discover(self) -> Optional[Path]:
        if self.path and Path(self.path).is_file():
            return Path(self.path)
        for candidate in CONFIG_SEARCH:
            if candidate and Path(candidate).is_file():
                return Path(candidate)
        return None

    def load(self, path: Optional[Path] = None) -> "Config":
        """Load configuration, merging on top of the built-in defaults."""
        if path:
            self.path = Path(path)
        found = self._discover()
        if not found:
            return self
        self.loaded_from = found
        try:
            import yaml  # type: ignore
            with open(found, "r") as handle:
                user_cfg = yaml.safe_load(handle) or {}
            if isinstance(user_cfg, Mapping):
                self.data = _deep_merge(DEFAULT_CONFIG, user_cfg)
        except ImportError:
            self.data = _deep_merge(DEFAULT_CONFIG, _parse_yaml_tiny(found))
        except Exception as exc:  # noqa: BLE001 - config must never crash a tool
            print(f"[cyberlib] WARNING: could not parse {found}: {exc}", file=sys.stderr)
        return self

    # -- access ------------------------------------------------------------- #
    def get(self, dotted: str, default: Any = None) -> Any:
        """Return the value at ``section.key`` (or nested ``a.b.c``).

        A few keys can be overridden from the environment so the suite can be
        run from a checkout or relocated install without editing the config:
        ``CYBERDECK_INSTALL_DIR`` wins over ``general.install_dir`` and
        ``CYBERDECK_LOG_LEVEL`` over ``general.log_level``.
        """
        override = _ENV_OVERRIDES.get(dotted)
        if override:
            from_env = os.environ.get(override, "")
            if from_env:
                return from_env
        node: Any = self.data
        for part in dotted.split("."):
            if isinstance(node, Mapping) and part in node:
                node = node[part]
            else:
                return default
        return node

    def set(self, dotted: str, value: Any) -> None:
        """Set ``section.key`` in memory (call :meth:`save` to persist)."""
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
        self.dirty[dotted] = value

    def as_dict(self) -> Dict[str, Any]:
        """Return the merged configuration as a plain dict."""
        return json.loads(json.dumps(self.data, default=str))

    def save(self, path: Optional[Path] = None) -> Path:
        """Persist the configuration back to disk (YAML, creation mode 0600).

        Only the keys changed through :meth:`set` are written back. The shipped
        configuration is heavily commented, so a line-based edit keeps those
        comments and the operator's layout intact; if a changed key cannot be
        located the whole document is rewritten as a last resort.
        """
        target = Path(path) if path else (self.loaded_from or INSTALL_DIR / "cyberdeck.conf")
        target.parent.mkdir(parents=True, exist_ok=True)
        text: Optional[str] = None
        if self.dirty and target.is_file():
            try:
                text = self._patch_lines(target.read_text())
            except OSError as exc:
                logger.debug(f"could not read {target} for a line edit: {exc}")
                text = None
        if text is None:
            try:
                import yaml  # type: ignore
                text = yaml.safe_dump(self.data, sort_keys=False, default_flow_style=False)
            except ImportError:
                text = json.dumps(self.data, indent=2)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(text)
        os.chmod(tmp, 0o600)
        tmp.replace(target)
        self.loaded_from = target
        self.dirty.clear()
        return target

    def _patch_lines(self, text: str) -> Optional[str]:
        """Apply the changed keys to *text* line by line.

        Args:
            text: the current configuration file contents.

        Returns:
            The updated text, or ``None`` when a key is not present in the file
            (the caller then rewrites the whole document).
        """
        lines = text.splitlines()
        remaining = dict(self.dirty)
        section: Optional[str] = None
        for index, raw in enumerate(lines):
            stripped = raw.split("#", 1)[0].rstrip()
            if not stripped.strip():
                continue
            if not stripped[0].isspace() and stripped.endswith(":"):
                section = stripped[:-1].strip()
                continue
            if not stripped[0].isspace() or ":" not in stripped:
                continue
            key = stripped.split(":", 1)[0].strip()
            dotted = f"{section}.{key}" if section else key
            if dotted not in remaining:
                continue
            # Keep any inline comment that followed the value
            _, _, tail = raw.partition(":")
            comment = ""
            if "#" in tail:
                comment = "  " + tail.split("#", 1)[1].strip()
                comment = "  # " + comment.strip()[1:].strip()
            indent = raw[:len(raw) - len(raw.lstrip())]
            lines[index] = f"{indent}{key}: {format_scalar(remaining.pop(dotted))}{comment}"
        if remaining:
            return None
        return "\n".join(lines) + ("\n" if text.endswith("\n") or lines else "")

    @property
    def install_dir(self) -> Path:
        """Configured install directory as a :class:`Path`."""
        return Path(self.get("general.install_dir", str(INSTALL_DIR)))

    def log_dir(self) -> Path:
        """Configured log directory as a :class:`Path`."""
        return self.install_dir / "logs"

    def data_dir(self) -> Path:
        """Configured data directory as a :class:`Path`."""
        return self.install_dir / "data"


def format_scalar(value: Any) -> str:
    """Render a Python value the way ``cyberdeck.conf`` writes it.

    Args:
        value: the value to render.

    Returns:
        The YAML scalar (or inline list) representation.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return '""'
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(format_scalar(item) for item in value) + "]"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or text.strip() != text or text.lower() in ("true", "false", "yes", "no",
                                                              "null", "on", "off"):
        return f'"{text}"'
    if any(character in text for character in ":#{}[]&*!|>%@`"):
        return f'"{text}"'
    if text[0] in "-?,":
        return f'"{text}"'
    return text


def _parse_yaml_tiny(path: Path) -> Dict[str, Any]:
    """Very small YAML subset parser used when PyYAML is unavailable.

    Handles the ``section:`` / ``  key: value`` structure used by
    ``cyberdeck.conf`` together with inline ``[a, b]`` lists and booleans.
    """
    result: Dict[str, Any] = {}
    section: Optional[str] = None
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" ") and line.endswith(":"):
            section = line[:-1].strip()
            result[section] = {}
            continue
        if ":" in line:
            key, _, value = line.strip().partition(":")
            key, value = key.strip(), value.strip()
            parsed: Any = value
            if value.lower() in ("true", "false"):
                parsed = value.lower() == "true"
            elif value.startswith("[") and value.endswith("]"):
                parsed = [v.strip().strip("\"'") for v in value[1:-1].split(",") if v.strip()]
            elif value.replace(".", "", 1).isdigit():
                parsed = float(value) if "." in value else int(value)
            else:
                parsed = value.strip("\"'")
            if section:
                result[section][key] = parsed
            else:
                result[key] = parsed
    return result


# --------------------------------------------------------------------------- #
# Dependency / environment helpers
# --------------------------------------------------------------------------- #

class Dependencies:
    """Locate external binaries and Python modules, with graceful fallbacks."""

    def __init__(self) -> None:
        self._cache: Dict[str, Optional[str]] = {}

    def which(self, binary: str) -> Optional[str]:
        """Return the absolute path of *binary*, or ``None``."""
        if binary not in self._cache:
            self._cache[binary] = shutil.which(binary)
        return self._cache[binary]

    def have(self, binary: str) -> bool:
        """True when *binary* exists on ``$PATH``."""
        return self.which(binary) is not None

    def have_module(self, module: str) -> bool:
        """True when a Python module can be imported."""
        import importlib.util
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False

    def require(self, binaries: Sequence[str], component: str = "cyberdeck",
                logger: Optional[Logger] = None) -> bool:
        """Check a list of binaries; log (and optionally exit) when missing."""
        missing = [b for b in binaries if not self.have(b)]
        if missing:
            message = (f"{component}: missing required tool(s): {', '.join(missing)}. "
                       f"Install with: sudo pacman -S {' '.join(missing)}")
            if logger:
                logger.error(message)
            else:
                print(message, file=sys.stderr)
            return False
        return True

    def hint(self, binary: str, package: Optional[str] = None) -> str:
        """Return a one-line installation hint for a missing tool."""
        return f"'{binary}' not found - install with: sudo pacman -S {package or binary}"


deps = Dependencies()


def is_root() -> bool:
    """True when running with effective uid 0."""
    return os.geteuid() == 0


def require_root(component: str = "cyberdeck", logger: Optional[Logger] = None) -> bool:
    """Warn and return False when not running as root."""
    if is_root():
        return True
    message = f"{component} must be run as root (try: sudo {component})"
    if logger:
        logger.error(message)
    else:
        print(message, file=sys.stderr)
    return False


def have_connectivity(host: str = "1.1.1.1", port: int = 53, timeout: float = 3.0) -> bool:
    """Return True when a TCP connection to *host*:*port* succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(cmd: Sequence[str] | str, timeout: float = 30.0, shell: bool = False,
        check: bool = False, input_text: Optional[str] = None,
        logger: Optional[Logger] = None, env: Optional[Mapping[str, str]] = None
        ) -> Tuple[int, str, str]:
    """Run a command safely, returning ``(returncode, stdout, stderr)``.

    Never raises on non-zero exit (unless *check*), and never hangs the caller
    for longer than *timeout* seconds.
    """
    if isinstance(cmd, str):
        shell = True
    try:
        proc = subprocess.run(  # noqa: S603 - explicit, caller-controlled argv
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout,
            input=input_text, env=dict(env) if env else None,
        )
    except subprocess.TimeoutExpired:
        if logger:
            logger.debug(f"timeout after {timeout}s: {cmd}")
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {cmd}\n{proc.stderr}")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def run_streaming(cmd: Sequence[str] | str, on_line: Callable[[str], None],
                  timeout: float = 60.0, logger: Optional[Logger] = None) -> int:
    """Run a command, invoking *on_line* for each stdout line (live capture)."""
    shell = isinstance(cmd, str)
    try:
        proc = subprocess.Popen(  # noqa: S603
            cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
    except FileNotFoundError as exc:
        if logger:
            logger.error(str(exc))
        return 127
    deadline = time.time() + timeout
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            on_line(line.rstrip("\n"))
            if time.time() > deadline:
                proc.terminate()
                break
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return proc.returncode or 0


# --------------------------------------------------------------------------- #
# Hardware detection
# --------------------------------------------------------------------------- #

@dataclass
class Interface:
    """A network interface and what it is capable of."""

    name: str
    kind: str = "unknown"              # wifi | ethernet | monitor | other
    mac: str = "unknown"
    state: str = "unknown"
    driver: str = "unknown"
    chipset: str = "unknown"
    monitor_capable: bool = False
    supports_injection: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise the interface for JSON output."""
        return {
            "name": self.name, "kind": self.kind, "mac": self.mac, "state": self.state,
            "driver": self.driver, "chipset": self.chipset,
            "monitor_capable": self.monitor_capable,
            "supports_injection": self.supports_injection, **self.extra,
        }


class Hardware:
    """Best-effort hardware probing that never raises on a plain VM."""

    #: Chipsets with reliable monitor mode + injection under Linux
    KNOWN_MONITOR_CHIPSETS: Tuple[str, ...] = (
        "ath9k", "ath9k_htc", "ath10k", "rt2800usb", "rt73usb", "rtl8187",
        "rtl8812au", "rtl8814au", "rtl88xxau", "mt76", "mt7601u", "mt7921",
        "iwlwifi", "carl9170", "p54usb", "zd1211rw",
    )

    @staticmethod
    def interfaces() -> List[Interface]:
        """Enumerate network interfaces (via ``/sys/class/net``, no deps)."""
        found: List[Interface] = []
        net = Path("/sys/class/net")
        if not net.is_dir():
            return found
        for entry in sorted(net.iterdir()):
            iface = Interface(name=entry.name)
            try:
                iface.mac = (entry / "address").read_text().strip()
            except OSError:
                pass
            try:
                iface.state = (entry / "operstate").read_text().strip()
            except OSError:
                pass
            try:
                if (entry / "device").exists():
                    iface.driver = (entry / "device" / "driver").resolve().name
                else:
                    iface.driver = "virtual"
            except OSError:
                iface.driver = "unknown"
            if (entry / "wireless").exists():
                iface.kind = "wifi"
            elif entry.name == "lo":
                iface.kind = "loopback"
            elif iface.name.startswith(("wl",)):
                iface.kind = "wifi"
            elif iface.name.startswith(("eth", "en")):
                iface.kind = "ethernet"
            if iface.driver in Hardware.KNOWN_MONITOR_CHIPSETS:
                iface.monitor_capable = True
                iface.supports_injection = True
            if iface.kind == "wifi" and iface.driver in ("unknown", "virtio_net"):
                # Unknown wireless driver: assume monitor capable only if `iw` says so
                if is_root() and deps.have("iw"):
                    _, out, _ = run(["iw", "phy"], timeout=5)
                    if f"{iface.name}" in run(["iw", "dev"], timeout=5)[1]:
                        iface.monitor_capable = "monitor" in out
            found.append(iface)
        return found

    @staticmethod
    def wifi_interfaces() -> List[Interface]:
        """Return only wireless interfaces."""
        return [i for i in Hardware.interfaces() if i.kind == "wifi"]

    @staticmethod
    def monitor_capable() -> List[Interface]:
        """Return wireless interfaces considered capable of monitor mode."""
        return [i for i in Hardware.wifi_interfaces() if i.monitor_capable]

    @staticmethod
    def sdr_devices() -> List[Dict[str, str]]:
        """Return detected SDR receivers (RTL-SDR, HackRF, Airspy, LimeSDR...)."""
        devices: List[Dict[str, str]] = []
        try:
            for entry in Path("/sys/bus/usb/devices").iterdir():
                for fname in ("manufacturer", "product"):
                    path = entry / fname
                    if not path.exists():
                        continue
                    try:
                        text = path.read_text().strip()
                    except OSError:
                        continue
                    low = text.lower()
                    if any(k in low for k in ("rtl", "realtek", "hackrf", "airspy",
                                              "limesdr", "sdrplay", "funcube",
                                              "nooelec", "dvbsky", "ezcap")):
                        devices.append({"bus": entry.name, "description": text})
        except OSError:
            pass
        if deps.have("rtl_test"):
            code, out, _ = run(["rtl_test", "-t"], timeout=6)
            if code == 0 and "Found" in out:
                devices.append({"bus": "rtl_test", "description": out.splitlines()[0]})
        deduped: Dict[str, Dict[str, str]] = {}
        for device in devices:
            deduped.setdefault(device["description"], device)
        return list(deduped.values())

    @staticmethod
    def proxmark() -> bool:
        """True when the Proxmark3 client and a device are present."""
        if not deps.have("pm3") and not deps.have("proxmark3"):
            return False
        return any(p.exists() for p in (Path("/dev/ttyACM0"), Path("/dev/ttyACM1")))

    @staticmethod
    def gps_device() -> Optional[str]:
        """Return a character device that looks like a GPS receiver."""
        candidates: List[Path] = []
        candidates += sorted(Path("/dev").glob("ttyACM*"))
        candidates += sorted(Path("/dev").glob("ttyUSB*"))
        candidates += sorted(Path("/dev").glob("gps*"))
        return str(candidates[0]) if candidates else None

    @staticmethod
    def gpio_available() -> bool:
        """True when running on a board with user-accessible GPIO."""
        if Path("/sys/class/gpio").exists() and Path("/proc/device-tree/model").exists():
            return True
        model = Path("/proc/device-tree/model")
        if model.exists():
            try:
                return any(k in model.read_text(errors="replace").lower()
                           for k in ("raspberry", "banana", "orange pi", "rock pi", "jetson"))
            except OSError:
                return False
        return False

    @staticmethod
    def model() -> str:
        """Return the board model string, or a generic description."""
        model = Path("/proc/device-tree/model")
        if model.exists():
            try:
                return model.read_text(errors="replace").strip("\x00").strip()
            except OSError:
                pass
        vendor = Path("/sys/devices/virtual/dmi/id/sys_vendor")
        product = Path("/sys/devices/virtual/dmi/id/product_name")
        if product.exists():
            try:
                return f"{vendor.read_text().strip()} {product.read_text().strip()}".strip()
            except OSError:
                pass
        return "generic x86_64 host"

    @staticmethod
    def battery() -> Optional[Dict[str, Any]]:
        """Return ``{percent, status, seconds_left}`` for the first battery."""
        for supply in sorted(Path("/sys/class/power_supply").glob("BAT*")):
            try:
                percent = int((supply / "capacity").read_text().strip())
            except (OSError, ValueError):
                continue
            status = "Unknown"
            try:
                status = (supply / "status").read_text().strip()
            except OSError:
                pass
            return {"percent": percent, "status": status, "path": str(supply)}
        return None

    @staticmethod
    def temperature() -> Optional[float]:
        """Return the highest thermal-zone temperature in degrees Celsius."""
        readings: List[float] = []
        for zone in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
            try:
                value = float(zone.read_text().strip())
            except (OSError, ValueError):
                continue
            readings.append(value / 1000.0 if value > 1000 else value)
        return max(readings) if readings else None

    @staticmethod
    def vitals() -> Dict[str, Any]:
        """Return a vitals snapshot (CPU, RAM, disk, temp, battery, uptime)."""
        data: Dict[str, Any] = {
            "cpu_percent": None, "ram_percent": None, "ram_used_mb": None,
            "ram_total_mb": None, "disk_percent": None, "temperature": None,
            "battery": None, "uptime_seconds": None, "load_avg": None,
            "cpu_count": os.cpu_count(),
        }
        if deps.have_module("psutil"):
            import psutil  # type: ignore
            data["cpu_percent"] = psutil.cpu_percent(interval=0.15)
            mem = psutil.virtual_memory()
            data["ram_percent"] = mem.percent
            data["ram_used_mb"] = round(mem.used / 1048576, 1)
            data["ram_total_mb"] = round(mem.total / 1048576, 1)
            try:
                data["disk_percent"] = psutil.disk_usage("/").percent
            except OSError:
                pass
            data["uptime_seconds"] = time.time() - psutil.boot_time()
        elif Path("/proc/meminfo").exists():
            info = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                key, _, value = line.partition(":")
                info[key] = value.strip()
            total = int(info.get("MemTotal", "0 kB").split()[0])
            available = int(info.get("MemAvailable", "0 kB").split()[0])
            if total:
                data["ram_total_mb"] = round(total / 1024, 1)
                data["ram_used_mb"] = round((total - available) / 1024, 1)
                data["ram_percent"] = round(100 * (total - available) / total, 1)
        try:
            data["load_avg"] = os.getloadavg()
        except OSError:
            pass
        if data["uptime_seconds"] is None and Path("/proc/uptime").exists():
            try:
                data["uptime_seconds"] = float(Path("/proc/uptime").read_text().split()[0])
            except (OSError, ValueError):
                pass
        data["temperature"] = Hardware.temperature()
        data["battery"] = Hardware.battery()
        return data

    @staticmethod
    def summary() -> List[Tuple[str, str, str]]:
        """Return a ``(component, status, detail)`` list for the status command."""
        rows: List[Tuple[str, str, str]] = []
        wifi = Hardware.wifi_interfaces()
        rows.append(("WiFi interfaces", "ok" if wifi else "absent",
                     ", ".join(f"{i.name} ({i.driver})" for i in wifi) or "no wireless NIC found"))
        monitors = Hardware.monitor_capable()
        rows.append(("Monitor mode", "ok" if monitors else "absent",
                     ", ".join(i.name for i in monitors) or "no monitor-capable adapter"))
        sdr = Hardware.sdr_devices()
        rows.append(("SDR receivers", "ok" if sdr else "absent",
                     "; ".join(d["description"] for d in sdr) or "none detected"))
        rows.append(("Proxmark/NFC", "ok" if Hardware.proxmark() else "absent",
                     "present" if Hardware.proxmark() else "not detected"))
        gps = Hardware.gps_device()
        rows.append(("GPS", "ok" if gps else "absent", gps or "no serial GPS detected"))
        rows.append(("GPIO", "ok" if Hardware.gpio_available() else "absent",
                     "available" if Hardware.gpio_available() else "not a GPIO single-board computer"))
        battery = Hardware.battery()
        rows.append(("Battery", "ok" if battery else "absent",
                     f"{battery['percent']}% ({battery['status']})" if battery else "mains powered"))
        return rows


# --------------------------------------------------------------------------- #
# Databases
# --------------------------------------------------------------------------- #

SCHEMAS: Dict[str, str] = {
    "events": """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'INFO',
            message TEXT NOT NULL,
            data TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
    """,
    "probes": """
        CREATE TABLE IF NOT EXISTS probe_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source_mac TEXT NOT NULL,
            vendor TEXT,
            ssid TEXT,
            rssi INTEGER,
            channel INTEGER,
            random_mac INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_probe_mac ON probe_requests(source_mac);
        CREATE TABLE IF NOT EXISTS devices (
            source_mac TEXT PRIMARY KEY,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 1,
            strongest_rssi INTEGER,
            probed_ssids TEXT DEFAULT '[]',
            notes TEXT,
            risk TEXT DEFAULT 'unknown'
        );
    """,
    "ble": """
        CREATE TABLE IF NOT EXISTS ble_devices (
            address TEXT PRIMARY KEY,
            name TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 1,
            last_rssi INTEGER,
            manufacturer_data TEXT,
            service_uuids TEXT,
            vulnerable INTEGER DEFAULT 0,
            cve_refs TEXT
        );
        CREATE TABLE IF NOT EXISTS ble_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            address TEXT NOT NULL,
            rssi INTEGER,
            channel INTEGER
        );
    """,
    "arp": """
        CREATE TABLE IF NOT EXISTS arp_hosts (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            os_guess TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            packets INTEGER DEFAULT 1,
            gateway INTEGER DEFAULT 0,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS arp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            event TEXT NOT NULL,
            detail TEXT
        );
    """,
    "services": """
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            protocol TEXT NOT NULL,
            host TEXT,
            port INTEGER,
            service TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_services_host ON services(host);
    """,
    "baseline": """
        CREATE TABLE IF NOT EXISTS ap_baseline (
            bssid TEXT PRIMARY KEY,
            ssid TEXT,
            channel INTEGER,
            encryption TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            sightings INTEGER DEFAULT 1,
            trusted INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ap_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            bssid TEXT,
            ssid TEXT,
            kind TEXT NOT NULL,
            detail TEXT,
            acknowledged INTEGER DEFAULT 0
        );
    """,
    "payloads": """
        CREATE TABLE IF NOT EXISTS payload_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT,
            path TEXT,
            status INTEGER,
            bytes INTEGER,
            user_agent TEXT,
            referer TEXT,
            note TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_payload_ts ON payload_requests(ts);
        CREATE INDEX IF NOT EXISTS idx_payload_ip ON payload_requests(client_ip);
        CREATE TABLE IF NOT EXISTS payload_callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            port INTEGER,
            banner TEXT,
            note TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_callback_ts ON payload_callbacks(ts);
    """,
    "usb": """
        CREATE TABLE IF NOT EXISTS usb_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            action TEXT NOT NULL,
            vendor_id TEXT,
            product_id TEXT,
            serial TEXT,
            manufacturer TEXT,
            product TEXT,
            device_node TEXT,
            sha256 TEXT,
            notes TEXT
        );
    """,
    "alerts": """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            acknowledged INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
    """,
    "customers": "",  # placeholder key kept so unknown schemas raise cleanly
}


class Database:
    """Thin SQLite wrapper: schema creation, upserts, event log and feed reads."""

    def __init__(self, name: str, path: Optional[Path] = None, logger: Optional[Logger] = None) -> None:
        """Open (creating if needed) the database called *name*."""
        self.name = name
        self.logger = logger
        base = DATA_DIR
        try:
            base.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            base = Path.home() / ".cyberdeck-arsenal" / "data"
            base.mkdir(parents=True, exist_ok=True)
        self.path = Path(path) if path else base / f"{name}.db"
        try:
            self.conn = sqlite3.connect(str(self.path), timeout=10,
                                        check_same_thread=False)
        except sqlite3.Error:
            fallback = Path.home() / ".cyberdeck-arsenal" / "data"
            fallback.mkdir(parents=True, exist_ok=True)
            self.path = fallback / f"{name}.db"
            self.conn = sqlite3.connect(str(self.path), timeout=10,
                                        check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error:
            pass
        schema = SCHEMAS.get(name, "")
        if name == "events":
            # The events log mirrors alerts into the same database file.
            schema += SCHEMAS.get("alerts", "")
        if schema:
            self.conn.executescript(schema)
            self.conn.commit()

    # -- generic ------------------------------------------------------------ #
    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        """Execute a statement and commit."""
        cursor = self.conn.execute(sql, params)
        self.conn.commit()
        return cursor

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        """Run a SELECT and return all rows."""
        return list(self.conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        """Run a SELECT and return the first row (or None)."""
        row = self.conn.execute(sql, params).fetchone()
        return row

    def upsert(self, table: str, key_columns: Sequence[str], data: Mapping[str, Any]) -> None:
        """Insert *data* into *table*, updating on conflict of *key_columns*."""
        columns = list(data.keys())
        placeholders = ", ".join("?" for _ in columns)
        updates = ", ".join(f"{c}=excluded.{c}" for c in columns if c not in key_columns)
        conflict = ", ".join(key_columns)
        sql = (f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
               f"ON CONFLICT({conflict}) DO UPDATE SET {updates}")
        self.execute(sql, [data[c] for c in columns])

    def event(self, source: str, category: str, message: str, severity: str = "INFO",
              data: Optional[Mapping[str, Any]] = None) -> None:
        """Append to the shared event log (also mirrored into ``alerts``)."""
        payload = json.dumps(data) if data else None
        self.execute(
            "INSERT INTO events (ts, source, category, severity, message, data) "
            "VALUES (?,?,?,?,?,?)",
            (now_iso(), source, category, severity, message, payload))
        if severity.upper() in ("WARNING", "ALERT", "ERROR", "CRITICAL"):
            self.alert(source, severity, message, payload)

    def alert(self, source: str, severity: str, title: str, body: Optional[str] = None) -> None:
        """Append to the alert feed table (best effort)."""
        try:
            self.execute(
                "INSERT INTO alerts (ts, source, severity, title, body) VALUES (?,?,?,?,?)",
                (now_iso(), source, severity.upper(), title, body))
        except sqlite3.Error:
            pass

    def recent_alerts(self, limit: int = 8, since_hours: int = 24) -> List[sqlite3.Row]:
        """Return the most recent alerts from the last *since_hours* hours."""
        try:
            return self.query(
                "SELECT * FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                (iso_hours_ago(since_hours), limit))
        except sqlite3.Error:
            return []

    def prune(self, table: str, keep_days: int = 30, ts_column: str = "ts") -> int:
        """Delete rows older than *keep_days*; returns the number removed."""
        cursor = self.execute(
            f"DELETE FROM {table} WHERE {ts_column} < ?", (iso_days_ago(keep_days),))
        return cursor.rowcount or 0

    def close(self) -> None:
        """Checkpoint and close the connection."""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# OUI lookup
# --------------------------------------------------------------------------- #

class OuiLookup:
    """MAC-address to vendor resolution using the bundled OUI database."""

    _paths: Tuple[Path, ...] = (
        DATA_DIR / "oui_database.txt",
        INSTALL_DIR / "data" / "oui_database.txt",
        REPO_DIR / "data" / "oui_database.txt",
    )

    def __init__(self, path: Optional[Path] = None) -> None:
        """Load the OUI table (lazily, once per process)."""
        self.table: Dict[str, str] = {}
        candidates = (Path(path),) if path else self._paths
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                self._load(Path(candidate))
                break

    def _load(self, path: Path) -> None:
        try:
            for line in path.read_text(errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                prefix = parts[0].replace("-", ":").upper()
                if len(prefix) >= 8:
                    self.table[prefix[:8]] = parts[1].strip()
        except OSError:
            pass

    def vendor(self, mac: str) -> str:
        """Return the vendor for *mac*, 'Randomised' for local bit, or 'Unknown'."""
        if not mac:
            return "Unknown"
        clean = mac.replace("-", ":").upper()
        if len(clean) < 8:
            return "Unknown"
        try:
            first_octet = int(clean.split(":")[0], 16)
        except (IndexError, ValueError):
            return "Unknown"
        # Bit 1 of the first octet is the U/L (locally administered) flag, which
        # is what modern phones set when they randomise their MAC address.
        if first_octet & 0x02:
            return "Randomised (locally administered)"
        return self.table.get(clean[:8], "Unknown")

    def is_randomised(self, mac: str) -> bool:
        """True when the MAC has the locally-administered (randomised) bit set."""
        try:
            return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0x02)
        except (IndexError, ValueError):
            return False


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #

class Alerts:
    """Fan-out alert dispatcher: console, DB feed, desktop, webhook, LED hook."""

    def __init__(self, source: str, config: Optional[Config] = None,
                 logger: Optional[Logger] = None) -> None:
        """Bind the dispatcher to a component name and configuration."""
        self.source = source
        self.config = config or Config().load()
        self.logger = logger or Logger(source, level=config_log_level(self.config))
        self.webhook = str(self.config.get("alerts.webhook_url", "") or "")
        self.desktop = bool(self.config.get("alerts.desktop_notifications", True))
        self.db = Database("alerts", logger=self.logger)
        self._led_hook: Optional[Callable[[str], None]] = None

    def register_led_hook(self, hook: Callable[[str], None]) -> None:
        """Register a callback (e.g. the GPIO LED controller) for alert severities."""
        self._led_hook = hook

    def send(self, title: str, body: str = "", severity: str = "INFO",
             data: Optional[Mapping[str, Any]] = None) -> None:
        """Dispatch an alert through every configured channel."""
        severity = severity.upper()
        self.db.alert(self.source, severity, title, body)
        self.logger.alert(f"{title}{(' - ' + body) if body else ''}")
        if self.desktop and deps.have("notify-send"):
            run(["notify-send", "-a", "cyberdeck-arsenal", "-u",
                 "critical" if severity in ("CRITICAL", "ERROR") else "normal",
                 title, body], timeout=5)
        if self.webhook.startswith("http") and deps.have_module("requests"):
            import requests  # type: ignore
            payload = {"source": self.source, "severity": severity, "title": title,
                       "body": body, "ts": now_iso(), "data": dict(data or {})}
            try:
                requests.post(self.webhook, json=payload, timeout=6)
            except Exception as exc:  # noqa: BLE001 - never break the caller
                self.logger.debug(f"webhook delivery failed: {exc}")
        if self._led_hook:
            try:
                self._led_hook(severity)
            except Exception as exc:  # noqa: BLE001
                self.logger.debug(f"LED hook failed: {exc}")

    def close(self) -> None:
        """Release the alert database handle."""
        self.db.close()


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #

def now_iso() -> str:
    """Current local time as an ISO-8601 string (second precision)."""
    return datetime.now().astimezone().replace(microsecond=0).isoformat()


def utc_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def iso_days_ago(days: int) -> str:
    """ISO timestamp for *days* ago."""
    return (datetime.now().astimezone() - __import__("datetime").timedelta(days=days)
            ).replace(microsecond=0).isoformat()


def iso_hours_ago(hours: int) -> str:
    """ISO timestamp for *hours* ago."""
    return (datetime.now().astimezone() - __import__("datetime").timedelta(hours=hours)
            ).replace(microsecond=0).isoformat()


def human_duration(seconds: Optional[float]) -> str:
    """Format *seconds* as ``3d 4h 12m`` / ``12m 40s``."""
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def human_bytes(num: float) -> str:
    """Format a byte count as ``1.2 MB``."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def timestamp_slug() -> str:
    """Filesystem-safe timestamp, e.g. ``2026-10-16_142530``."""
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")


def slugify(text: str, max_length: int = 60) -> str:
    """Turn arbitrary text into a safe directory/file name."""
    keep = [c if (c.isalnum() or c in "-._") else "-" for c in text.strip()]
    slug = "".join(keep).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return (slug or "target")[:max_length]


def engagement_dir(target: str, base: Optional[Path] = None) -> Path:
    """Create and return ``<base>/<target>_<timestamp>`` for organised output."""
    root = Path(base) if base else (REPORT_DIR if REPORT_DIR.exists() else Path.cwd() / "reports")
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{slugify(target)}_{timestamp_slug()}"
    for sub in ("raw", "logs", "evidence"):
        (path / sub).mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> Path:
    """Write *data* as pretty JSON, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")
    return path


def read_json(path: Path, default: Any = None) -> Any:
    """Read JSON from *path*, returning *default* on any failure."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return default


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: Optional[Sequence[str]] = None) -> Path:
    """Write an iterable of mappings to CSV."""
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return path
    columns = list(fieldnames or rows[0].keys())
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


# --------------------------------------------------------------------------- #
# Legal gating
# --------------------------------------------------------------------------- #

LEGAL_BANNER = """\
┌───────────────────────────────────────────────────────────────────────────┐
│  ⚠  AUTHORISED USE ONLY                                                    │
│                                                                           │
│  cyberdeck-arsenal contains offensive security tooling. You may only use   │
│  the active and attack modules against systems, networks and radio         │
│  spectrum that you own or have explicit written authorisation to test.     │
│                                                                           │
│  Unauthorised interception, deauthentication, credential capture and       │
│  radio transmission are criminal offences in most jurisdictions (UK CMA    │
│  1990, US CFAA, DE StGB §202a-c) and may breach radio licensing rules.     │
│                                                                           │
│  The operator is solely responsible for compliance with all applicable     │
│  laws. See docs/LEGAL.md for the full notice.                              │
└───────────────────────────────────────────────────────────────────────────┘"""


def require_acknowledgement(config: Optional[Config] = None, logger: Optional[Logger] = None,
                            interactive: bool = True) -> bool:
    """Show the legal notice until acknowledged; returns True when acknowledged.

    The acknowledgement is persisted in the configuration file so it is only
    requested once (also set by ``setup.sh`` on first install).
    """
    cfg = config or Config().load()
    if cfg.get("general.authorised_use_acknowledged", False):
        return True
    print(colour(LEGAL_BANNER, C.YELLOW))
    if not interactive or not sys.stdin.isatty():
        if logger:
            logger.warn("legal notice not acknowledged (non-interactive); continuing")
        return False
    try:
        reply = input(colour("Type 'I AGREE' to confirm you are authorised to use these tools: ",
                             C.BRIGHT_RED))
    except (EOFError, KeyboardInterrupt):
        return False
    if reply.strip().upper() != "I AGREE":
        if logger:
            logger.error("authorisation not confirmed - refusing to continue")
        return False
    cfg.set("general.authorised_use_acknowledged", True)
    try:
        cfg.save()
    except OSError as exc:
        if logger:
            logger.debug(f"could not persist acknowledgement: {exc}")
    if logger:
        logger.ok("authorisation acknowledged - recorded in cyberdeck.conf")
    return True


def confirm(prompt: str, default: bool = False, logger: Optional[Logger] = None) -> bool:
    """Ask a yes/no question; non-interactive input falls back to *default*."""
    suffix = " [Y/n] " if default else " [y/N] "
    if not sys.stdin.isatty():
        return default
    try:
        reply = input(colour(prompt + suffix, C.BRIGHT_YELLOW)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not reply:
        return default
    if reply in ("y", "yes"):
        return True
    if logger:
        logger.warn("operator declined the action")
    return False


def config_log_level(config: Config) -> str:
    """Helper returning the configured log level."""
    return str(config.get("general.log_level", "INFO"))


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def selftest() -> int:
    """Run a quick smoke test of the library; returns a process exit code."""
    log = Logger("cyberlib-selftest", quiet=False)
    log.banner("cyberlib selftest", f"version {__version__}")
    cfg = Config().load()
    log.info(f"config: {cfg.loaded_from or 'defaults only'}")
    log.info(f"install dir: {cfg.install_dir}")
    log.info(f"root: {is_root()}   connectivity: {have_connectivity()}")
    for iface in Hardware.interfaces()[:6]:
        log.info(f"iface {iface.name}: {iface.kind} {iface.mac} driver={iface.driver} "
                 f"monitor={iface.monitor_capable}")
    vitals = Hardware.vitals()
    log.info(f"cpu={vitals['cpu_percent']} ram={vitals['ram_percent']}% "
             f"temp={vitals['temperature']} battery={vitals['battery']}")
    oui = OuiLookup()
    log.info(f"OUI entries loaded: {len(oui.table)}")
    db = Database("alerts", logger=log)
    db.event("selftest", "selftest", "library selftest executed", "INFO")
    log.ok(f"database writable at {db.path}")
    db.close()
    log.ok("selftest complete")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point: ``python3 cyberlib.py [--json-status]``."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="cyberlib", description="cyberdeck-arsenal shared library utilities")
    parser.add_argument("--json-status", action="store_true",
                        help="print a machine-readable hardware status snapshot")
    parser.add_argument("--config", help="print the resolved configuration as JSON")
    parser.add_argument("--vendor", metavar="MAC", help="resolve a MAC address vendor")
    parser.add_argument("--version", action="version", version=f"cyberlib {__version__}")
    args = parser.parse_args(argv)

    if args.json_status:
        payload = {
            "board": Hardware.model(),
            "interfaces": [i.as_dict() for i in Hardware.interfaces()],
            "sdr": Hardware.sdr_devices(),
            "gps": Hardware.gps_device(),
            "gpio": Hardware.gpio_available(),
            "proxmark": Hardware.proxmark(),
            "vitals": Hardware.vitals(),
            "root": is_root(),
            "connectivity": have_connectivity(),
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0
    if args.config:
        print(json.dumps(Config().load().as_dict(), indent=2))
        return 0
    if args.vendor:
        lookup = OuiLookup()
        print(f"{args.vendor}: {lookup.vendor(args.vendor)}")
        return 0
    return selftest()


if __name__ == "__main__":
    ensure_dirs()
    sys.exit(main())
