#!/usr/bin/env python3
"""
automation/triggers.py - event driven rules engine for the cyberdeck.
=====================================================================

Description
-----------
Watches the platform's own event sources and runs rules when something of
interest happens. Instead of a wall of shell one-liners, rules live in
``data/triggers.json`` (seeded on first run) and are evaluated by a small,
sandboxed expression evaluator, so a rule can be written like this::

    {
      "name": "badusb detected",
      "when": "source == 'usb_watcher' and severity in ('HIGH','CRITICAL')",
      "actions": [
        {"type": "alert", "severity": "CRITICAL", "message": "possible BadUSB: {message}"},
        {"type": "notify", "title": "USB", "message": "{message}"}
      ],
      "cooldown_s": 120
    }

Sources
-------
* ``db``   - new rows in any of the shared SQLite tables (events, alerts,
             probes, ble, arp, services, usb, baseline)
* ``file`` - a file that exists or that has just been written
* ``system`` - CPU load, memory, disk space, battery, temperature, uptime
* ``net``  - interface state, default route, connectivity

Actions
-------
``alert``, ``event``, ``notify``, ``run`` (command, sandboxed to an allow-list),
``unit`` (start/stop/restart a systemd unit from the cyberdeck set), ``theme``
(aesthetic/theme_switcher.sh), ``panic`` (asks for confirmation, then calls
utilities/self_destruct.sh), ``report`` (recon/reporting/report_generator.py).

Safety: conditions are parsed with :mod:`ast` and only a small set of node types
is allowed, so a rule cannot execute arbitrary code; commands must be listed in
``automation.allowed_commands`` in cyberdeck.conf; ``panic`` always confirms
unless ``--yes`` was given on the command line.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library (optional: systemd, notify-send, libnotify)
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Usage
-----
    ./triggers.py --list
    ./triggers.py --watch                  # daemon loop, poll every 5s
    ./triggers.py --once --dry-run          # evaluate and print, change nothing
    ./triggers.py --test "source == 'usb_watcher'" --with severity=HIGH
"""

from __future__ import annotations

import argparse
import ast
import json
import operator
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

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
        Alerts,
        Config,
        Database,
        Logger,
        colour,
        human_bytes,
        now_iso,
        run,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: Datasets the db source can watch, and the column used for incremental reads
DB_SOURCES: Dict[str, Tuple[str, str]] = {
    "events": ("events", "id"),
    "alerts": ("alerts", "id"),
    "probes": ("probe_requests", "id"),
    "ble": ("ble_sightings", "id"),
    "arp": ("arp_events", "id"),
    "services": ("services", "id"),
    "usb": ("usb_devices", "id"),
}

#: Default rules, written to data/triggers.json the first time the tool runs
DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "name": "possible badusb",
        "description": "A USB device that can type was plugged in - classic BadUSB shape",
        "when": "source == 'usb_watcher' and severity in ('HIGH', 'CRITICAL')",
        "actions": [
            {"type": "alert", "severity": "CRITICAL",
             "message": "possible BadUSB device: {message}"},
            {"type": "notify", "title": "USB device", "message": "{message}"},
        ],
        "cooldown_s": 60,
    },
    {
        "name": "rogue access point",
        "description": "An access point that is not in the baseline appeared",
        "when": "source == 'rogue_ap_detector' or category == 'rogue_ap'",
        "actions": [
            {"type": "alert", "severity": "HIGH", "message": "rogue AP: {message}"},
            {"type": "notify", "title": "Wireless", "message": "rogue AP: {message}"},
        ],
        "cooldown_s": 120,
    },
    {
        "name": "new host on the network",
        "description": "A MAC other than the configured gateway appeared on the segment",
        "when": "source == 'arp_mapper' and severity == 'HIGH'",
        "actions": [
            {"type": "event", "message": "new host: {message}"},
            {"type": "notify", "title": "Network", "message": "{message}"},
        ],
        "cooldown_s": 30,
    },
    {
        "name": "probe request flood",
        "description": "One device sent an unusual number of probe requests",
        "when": "source == 'wifi_probe_logger' and count >= 60",
        "actions": [
            {"type": "event", "message": "probe flood: {message}"},
        ],
        "cooldown_s": 300,
    },
    {
        "name": "disk almost full",
        "description": "Captures fill disks faster than anything else on a deck",
        "when": "kind == 'system' and disk_percent >= 90",
        "actions": [
            {"type": "notify", "title": "Disk", "message": "root filesystem "
                                                          "{disk_percent}% full"},
            {"type": "event", "message": "disk at {disk_percent}%"},
        ],
        "cooldown_s": 900,
    },
    {
        "name": "battery low",
        "description": "Warn before a laptop deck dies mid-engagement",
        "when": "kind == 'system' and battery_percent is not None and battery_percent <= 15 "
                "and battery_status != 'Charging'",
        "actions": [
            {"type": "notify", "title": "Battery", "message": "battery at "
                                                              "{battery_percent}% - find power"},
            {"type": "event", "message": "battery low: {battery_percent}%"},
        ],
        "cooldown_s": 600,
    },
    {
        "name": "thermal pressure",
        "description": "Sustained hashcat or SDR work overheats small decks",
        "when": "kind == 'system' and temperature_c >= 85",
        "actions": [
            {"type": "notify", "title": "Thermal", "message": "CPU at {temperature_c} C"},
            {"type": "event", "message": "thermal event {temperature_c} C"},
        ],
        "cooldown_s": 300,
    },
    {
        "name": "connectivity lost",
        "description": "The deck lost its default route (cable pulled, radio down)",
        "when": "kind == 'net' and online == False",
        "actions": [
            {"type": "event", "message": "connectivity lost on {interface}"},
        ],
        "cooldown_s": 120,
    },
    {
        "name": "new capture to hash",
        "description": "Anything written into captures/ gets hashed into the custody log",
        "when": "kind == 'file' and contains(path, 'captures/') and endswith(path, '.pcap')",
        "actions": [
            {"type": "run", "command": "evidence_hasher.py",
             "args": "seal {path}", "allow_key": "evidence_hasher"},
        ],
        "cooldown_s": 30,
    },
    {
        "name": "authentication attack spotted",
        "description": "The service watcher saw repeated authentication failures",
        "when": "source == 'service_watcher' and severity in ('HIGH', 'CRITICAL')",
        "actions": [
            {"type": "alert", "severity": "HIGH", "message": "possible brute force: {message}"},
        ],
        "cooldown_s": 300,
    },
]

#: Expression nodes the sandboxed evaluator accepts
ALLOWED_NODES: Tuple[type, ...] = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Compare,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Is, ast.IsNot, ast.Name, ast.Load, ast.Constant, ast.Attribute, ast.Call,
    ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Subscript, ast.IfExp,
)


class TriggerError(Exception):
    """Raised when a rule cannot be parsed or evaluated."""


# --------------------------------------------------------------------------- #
# Sandboxed expression evaluation
# --------------------------------------------------------------------------- #
class SafeEvaluator:
    """Evaluates rule conditions over a restricted namespace.

    The allowed syntax is deliberately narrow: comparisons, boolean logic,
    arithmetic, ``in``/``not in``, a handful of helper functions and attribute
    free names. Anything else (imports, lambdas, comprehensions, dunder access,
    assignment) raises :class:`TriggerError`.
    """

    def __init__(self) -> None:
        """Create the evaluator with its helper functions."""
        self.helpers: Dict[str, Callable[..., Any]] = {
            "contains": lambda haystack, needle: str(needle) in str(haystack),
            "startswith": lambda text, prefix: str(text).startswith(str(prefix)),
            "endswith": lambda text, suffix: str(text).endswith(str(suffix)),
            "lower": lambda text: str(text).lower(),
            "upper": lambda text: str(text).upper(),
            "len": len,
            "int": lambda value: int(float(value)),
            "float": lambda value: float(value),
            "str": str,
            "abs": abs,
            "min": min,
            "max": max,
            "round": round,
            "matches": lambda text, pattern: bool(re.search(str(pattern), str(text))),
            "now": now_iso,
            "hours_ago": lambda hours: (datetime.now().astimezone()
                                        - timedelta(hours=float(hours))).isoformat(),
        }

    def validate(self, expression: str) -> ast.Expression:
        """Parse an expression and check every node type.

        Args:
            expression: the rule condition.

        Returns:
            The parsed expression.

        Raises:
            TriggerError: when the expression uses unsupported syntax.
        """
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as exc:
            raise TriggerError(f"cannot parse the condition: {exc}") from exc
        for node in ast.walk(tree):
            if not isinstance(node, ALLOWED_NODES):
                raise TriggerError(
                    f"unsupported syntax in the condition: {type(node).__name__}")
            if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                raise TriggerError("attribute access starting with '_' is not allowed")
            if isinstance(node, ast.Name) and node.id.startswith("_"):
                raise TriggerError("names starting with '_' are not allowed")
        return tree

    def evaluate(self, expression: str, variables: Dict[str, Any]) -> Any:
        """Evaluate a condition.

        Args:
            expression: the rule condition.
            variables: the values available to the condition.

        Returns:
            The result of the expression.

        Raises:
            TriggerError: when the expression is invalid or references an
                unknown name.
        """
        tree = self.validate(expression)
        namespace: Dict[str, Any] = dict(self.helpers)
        namespace.update(variables)
        try:
            return eval(compile(tree, "<rule>", "eval"), {"__builtins__": {}}, namespace)  # noqa: S307
        except NameError as exc:
            raise TriggerError(f"unknown name in the condition: {exc}") from exc
        except TriggerError:
            raise
        except Exception as exc:  # noqa: BLE001 - report any evaluation problem
            raise TriggerError(f"condition failed: {exc}") from exc


# --------------------------------------------------------------------------- #
# Rule model
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    """One automation rule."""

    name: str
    when: str
    actions: List[Dict[str, Any]]
    description: str = ""
    enabled: bool = True
    cooldown_s: int = 60
    max_per_hour: int = 30
    last_fired: Optional[float] = None
    fire_times: List[float] = field(default_factory=list)
    fires: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        """Build a rule from its JSON representation.

        Args:
            data: the dictionary from triggers.json.

        Returns:
            The rule.

        Raises:
            TriggerError: when required fields are missing.
        """
        name = str(data.get("name", "")).strip()
        when = str(data.get("when", "")).strip()
        actions = list(data.get("actions") or [])
        if not name or not when or not actions:
            raise TriggerError(f"rule needs a name, a when clause and actions: {data}")
        return cls(
            name=name,
            when=when,
            actions=actions,
            description=str(data.get("description", "")),
            enabled=bool(data.get("enabled", True)),
            cooldown_s=int(data.get("cooldown_s", 60)),
            max_per_hour=int(data.get("max_per_hour", 30)),
        )

    def ready(self, now: Optional[float] = None) -> Tuple[bool, str]:
        """Check the cooldown and the hourly limit.

        Args:
            now: current monotonic-ish timestamp (defaults to time.time()).

        Returns:
            A ``(ready, reason)`` pair; the reason is '' when ready.
        """
        now = time.time() if now is None else now
        if not self.enabled:
            return False, "disabled"
        if self.last_fired is not None and now - self.last_fired < self.cooldown_s:
            remaining = int(self.cooldown_s - (now - self.last_fired))
            return False, f"cooling down for {remaining}s"
        hour_ago = now - 3600
        recent = [stamp for stamp in self.fire_times if stamp >= hour_ago]
        if len(recent) >= self.max_per_hour:
            return False, f"hourly limit reached ({self.max_per_hour})"
        return True, ""

    def mark_fired(self) -> None:
        """Record that the rule fired."""
        now = time.time()
        self.last_fired = now
        self.fires += 1
        self.fire_times.append(now)
        self.fire_times = [stamp for stamp in self.fire_times if stamp >= now - 3600]

    def as_dict(self) -> Dict[str, Any]:
        """Return the rule as a plain dictionary.

        Returns:
            The dictionary.
        """
        return {
            "name": self.name,
            "description": self.description,
            "when": self.when,
            "actions": self.actions,
            "enabled": self.enabled,
            "cooldown_s": self.cooldown_s,
            "max_per_hour": self.max_per_hour,
            "fires": self.fires,
            "last_fired": (datetime.fromtimestamp(self.last_fired).isoformat()
                           if self.last_fired else None),
        }


# --------------------------------------------------------------------------- #
# Event sources
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    """One piece of information handed to the rules."""

    kind: str
    source: str
    data: Dict[str, Any]
    timestamp: str = field(default_factory=now_iso)

    @property
    def message(self) -> str:
        """A one-line rendering of the event."""
        return str(self.data.get("message") or self.data.get("device")
                   or self.data.get("summary") or json.dumps(self.data)[:120])

    def variables(self) -> Dict[str, Any]:
        """Return the variables visible to rule conditions.

        Returns:
            A dictionary with the event payload plus convenience keys.
        """
        variables: Dict[str, Any] = {
            "kind": self.kind,
            "source": self.source,
            "timestamp": self.timestamp,
            "message": self.message,
        }
        variables.update(self.data)
        return variables

    def as_dict(self) -> Dict[str, Any]:
        """Return the event as a plain dictionary.

        Returns:
            The dictionary.
        """
        return {"kind": self.kind, "source": self.source,
                "timestamp": self.timestamp, "data": self.data}


class DatabaseWatcher:
    """Reads new rows from the shared SQLite databases."""

    #: Where the row cursors are kept between runs so a restart does not replay
    #: history and a stopped daemon still catches up on what it missed.
    CURSOR_FILE = "triggers_cursors.json"

    def __init__(self, install_dir: Path, logger: Logger) -> None:
        """Create the watcher.

        Args:
            install_dir: the install root holding ``data/*.db``.
            logger: shared logger.
        """
        self.data_dir = install_dir / "data"
        self.cursor_file = install_dir / "state" / self.CURSOR_FILE
        self.logger = logger
        #: table -> last row id seen
        self.cursors: Dict[str, int] = self.load_cursors()
        self.first_pass = not self.cursors

    def load_cursors(self) -> Dict[str, int]:
        """Load the saved row cursors.

        Returns:
            A mapping of table name to last row id; empty on first run.
        """
        if not self.cursor_file.is_file():
            return {}
        try:
            data = json.loads(self.cursor_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.debug("could not read %s: %s", self.cursor_file, exc)
            return {}
        cursors: Dict[str, int] = {}
        for key, value in (data.get("cursors", {}) or {}).items():
            try:
                cursors[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        return cursors

    def save_cursors(self) -> None:
        """Persist the row cursors."""
        try:
            self.cursor_file.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_file.write_text(json.dumps({
                "saved": now_iso(),
                "cursors": self.cursors,
            }, indent=2) + "\n")
            try:
                self.cursor_file.chmod(0o600)
            except OSError:  # pragma: no cover
                pass
        except OSError as exc:
            self.logger.debug("could not save the cursors: %s", exc)

    def _cursor_for(self, table: str) -> int:
        """Return the last seen id for a table, initialising on first use.

        Args:
            table: the table name.

        Returns:
            The last row id.
        """
        if table in self.cursors:
            return self.cursors[table]
        identifier = table.replace("'", "''")
        path = self._path_for(table)
        if path is None or not path.is_file():
            self.cursors[table] = 0
            return 0
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                row = connection.execute(f"SELECT COALESCE(MAX(id), 0) FROM {identifier}"
                                         ).fetchone()
            self.cursors[table] = int(row[0]) if row else 0
        except sqlite3.Error as exc:
            self.logger.debug("could not initialise the cursor for %s: %s", table, exc)
            self.cursors[table] = 0
        return self.cursors[table]

    def _path_for(self, table: str) -> Optional[Path]:
        """Find the database file that holds a table.

        Args:
            table: the table name.

        Returns:
            The path, or ``None`` when no database holds it.
        """
        for name in DB_SOURCES:
            candidate = self.data_dir / f"{name}.db"
            if not candidate.is_file():
                continue
            if table in ("events", "alerts") and name in ("events", "alerts"):
                return candidate
            try:
                with sqlite3.connect(f"file:{candidate}?mode=ro", uri=True) as connection:
                    found = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (table,)).fetchone()
                if found:
                    return candidate
            except sqlite3.Error:
                continue
        return None

    def poll(self) -> List[Event]:
        """Return the rows added since the last poll.

        Returns:
            A list of events, oldest first.
        """
        events: List[Event] = []
        for name, (table, id_column) in DB_SOURCES.items():
            path = self._path_for(table)
            if path is None or not path.is_file():
                continue
            last = self._cursor_for(table)
            if self.first_pass:
                # First ever run: only the newest rows matter, a fresh install
                # must not replay the whole history into the rules.
                self.cursors[table] = last
                continue
            try:
                with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                    connection.row_factory = sqlite3.Row
                    rows = connection.execute(
                        f"SELECT * FROM {table} WHERE {id_column} > ? "
                        f"ORDER BY {id_column} ASC LIMIT 200", (last,)).fetchall()
            except sqlite3.Error as exc:
                self.logger.debug("could not read %s: %s", table, exc)
                continue
            for row in rows:
                payload = dict(row)
                self.cursors[table] = max(self.cursors.get(table, 0),
                                          int(payload.get(id_column, 0)))
                events.append(Event(kind="db", source=str(payload.get("source", name)),
                                    data=payload))
        if self.first_pass:
            self.first_pass = False
        self.save_cursors()
        return events


class SystemWatcher:
    """Reads local system state that operators care about."""

    def __init__(self, install_dir: Path, logger: Logger) -> None:
        """Create the watcher.

        Args:
            install_dir: the install root (for disk statistics).
            logger: shared logger.
        """
        self.install_dir = install_dir
        self.logger = logger
        self.last: Dict[str, Any] = {}

    def sample(self) -> List[Event]:
        """Sample the system and return events for changed values.

        Returns:
            The events for this sample.
        """
        events: List[Event] = []
        state: Dict[str, Any] = {"kind": "system"}
        try:
            load = os.getloadavg()[0]
            cores = os.cpu_count() or 1
            state["load1"] = round(load, 2)
            state["load_percent"] = round(load / cores * 100, 1)
        except (OSError, AttributeError):  # pragma: no cover - non-linux
            pass
        memory = read_memory()
        state.update(memory)
        state.update(read_disk(self.install_dir))
        state.update(read_battery())
        state.update(read_thermal())
        state["uptime_s"] = read_uptime()

        changed = {key: value for key, value in state.items()
                   if key not in self.last or self.last[key] != value}
        self.last = dict(state)
        if changed:
            changed["kind"] = "system"
            changed["message"] = summarise_system(state)
            events.append(Event(kind="system", source="system", data=changed))

        interface, online = default_route()
        if self.last.get("interface") != interface or self.last.get("online") != online:
            events.append(Event(kind="net", source="net", data={
                "kind": "net", "interface": interface, "online": online,
                "message": f"network {'up' if online else 'down'} on {interface}",
            }))
            self.last["interface"] = interface
            self.last["online"] = online
        return events


def read_memory() -> Dict[str, Any]:
    """Read memory statistics from /proc/meminfo.

    Returns:
        A dictionary with totals and a percentage.
    """
    path = Path("/proc/meminfo")
    if not path.is_file():
        return {}
    values: Dict[str, int] = {}
    try:
        for line in path.read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.strip().split()
            if parts:
                values[key] = int(parts[0])
    except (OSError, ValueError):
        return {}
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    if not total:
        return {}
    used = total - available
    return {
        "memory_total_kb": total,
        "memory_used_kb": used,
        "memory_percent": round(used / total * 100, 1),
        "swap_used_kb": values.get("SwapTotal", 0) - values.get("SwapFree", 0),
    }


def read_disk(path: Path) -> Dict[str, Any]:
    """Read disk usage for the filesystem holding a path.

    Args:
        path: any path on the filesystem.

    Returns:
        A dictionary with the usage percentage and free space.
    """
    try:
        usage = shutil.disk_usage(path if path.exists() else Path("/"))
    except OSError:
        return {}
    return {
        "disk_total": usage.total,
        "disk_free": usage.free,
        "disk_percent": round((usage.total - usage.free) / usage.total * 100, 1),
        "disk_free_human": human_bytes(usage.free),
    }


def read_battery() -> Dict[str, Any]:
    """Read the first battery from sysfs.

    Returns:
        A dictionary with the percentage and status, or an empty dictionary.
    """
    base = Path("/sys/class/power_supply")
    if not base.is_dir():
        return {}
    for entry in sorted(base.iterdir()):
        type_file = entry / "type"
        capacity = entry / "capacity"
        if not capacity.is_file():
            continue
        try:
            if type_file.is_file() and "Battery" not in type_file.read_text():
                continue
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
        return {"battery_percent": percent, "battery_status": status,
                "battery_device": entry.name}
    return {}


def read_thermal() -> Dict[str, Any]:
    """Read the hottest thermal zone.

    Returns:
        A dictionary with the temperature in Celsius, or an empty dictionary.
    """
    base = Path("/sys/class/thermal")
    if not base.is_dir():
        return {}
    hottest: Optional[float] = None
    for entry in sorted(base.glob("thermal_zone*")):
        temp_file = entry / "temp"
        if not temp_file.is_file():
            continue
        try:
            value = float(temp_file.read_text().strip())
        except (OSError, ValueError):
            continue
        celsius = value / 1000.0 if value > 1000 else value
        if hottest is None or celsius > hottest:
            hottest = celsius
    if hottest is None:
        return {}
    return {"temperature_c": round(hottest, 1)}


def read_uptime() -> Optional[int]:
    """Return the system uptime in seconds.

    Returns:
        Uptime in seconds, or ``None`` when it cannot be read.
    """
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def default_route() -> Tuple[str, bool]:
    """Return the default route interface and whether it is up.

    Returns:
        A ``(interface, online)`` pair.
    """
    try:
        with sqlite3.connect(":memory:") as _unused:  # keeps sqlite imported in faulthandler dumps
            pass
    except sqlite3.Error:  # pragma: no cover
        pass
    try:
        result = subprocess.run(["ip", "route", "show", "default"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
        fields = result.stdout.decode(errors="replace").split()
        if "dev" in fields:
            index = fields.index("dev")
            return fields[index + 1], True
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        pass
    return "", False


def summarise_system(state: Dict[str, Any]) -> str:
    """Build a one-line summary of a system sample.

    Args:
        state: the sampled values.

    Returns:
        The summary string.
    """
    parts = []
    if "load_percent" in state:
        parts.append(f"load {state['load_percent']}%")
    if "memory_percent" in state:
        parts.append(f"mem {state['memory_percent']}%")
    if "disk_percent" in state:
        parts.append(f"disk {state['disk_percent']}%")
    if "battery_percent" in state:
        parts.append(f"battery {state['battery_percent']}%")
    if "temperature_c" in state:
        parts.append(f"{state['temperature_c']} C")
    return ", ".join(parts) or "system sample"


class FileWatcher:
    """Watches directories for new or changed files."""

    def __init__(self, paths: Sequence[Path], logger: Logger) -> None:
        """Create the watcher.

        Args:
            paths: directories or files to watch.
            logger: shared logger.
        """
        self.paths = [path for path in paths]
        self.logger = logger
        self.known: Dict[str, float] = {}
        self.first_pass = True

    def poll(self, limit: int = 25) -> List[Event]:
        """Return events for files that appeared or changed.

        Args:
            limit: cap on the number of events per poll.

        Returns:
            The events.
        """
        events: List[Event] = []
        seen = 0
        for root in self.paths:
            if not root.exists():
                continue
            candidates: Iterable[Path]
            if root.is_file():
                candidates = [root]
            else:
                candidates = sorted(root.rglob("*"))
            for path in candidates:
                if seen >= limit:
                    break
                if not path.is_file():
                    continue
                try:
                    stamp = path.stat().st_mtime
                except OSError:
                    continue
                key = str(path)
                previous = self.known.get(key)
                self.known[key] = stamp
                if self.first_pass or previous is None or previous == stamp:
                    continue
                seen += 1
                events.append(Event(kind="file", source="file", data={
                    "kind": "file",
                    "path": key,
                    "size": path.stat().st_size,
                    "modified": datetime.fromtimestamp(stamp).isoformat(timespec="seconds"),
                    "message": f"{path.name} written to {path.parent}",
                }))
        self.first_pass = False
        return events


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class TriggerEngine:
    """Loads rules, evaluates events and performs actions.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
        rules_path: path to the rules file (defaults to data/triggers.json).
    """

    def __init__(self, config: Config, logger: Logger,
                 rules_path: Optional[Path] = None) -> None:
        """Create the engine."""
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                               "/opt/cyberdeck-arsenal")))
        self.rules_path = rules_path or (self.install_dir / "data" / "triggers.json")
        self.evaluator = SafeEvaluator()
        self.rules: List[Rule] = []
        self.dry_run = False
        self.assume_yes = False
        self.alerts = Alerts("trigger_engine", config, logger)
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)
        self.fired: List[Dict[str, Any]] = []
        #: rules whose condition has already been reported as broken
        self.reported: set = set()

    # -- loading ----------------------------------------------------------- #
    def ensure_rules_file(self, force: bool = False) -> Path:
        """Write the default rules file when it is missing.

        Args:
            force: overwrite an existing file.

        Returns:
            The path of the rules file.
        """
        if self.rules_path.is_file() and not force:
            return self.rules_path
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        self.rules_path.write_text(json.dumps(DEFAULT_RULES, indent=2) + "\n")
        self.logger.info("default rules written to %s", self.rules_path)
        return self.rules_path

    def load_rules(self) -> List[Rule]:
        """Load and validate the rules.

        Returns:
            The loaded rules.

        Raises:
            TriggerError: when the file cannot be parsed.
        """
        path = self.ensure_rules_file()
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise TriggerError(f"cannot read {path}: {exc}") from exc
        if isinstance(data, dict):
            data = data.get("rules", [])
        if not isinstance(data, list):
            raise TriggerError(f"{path} must contain a list of rules")
        rules: List[Rule] = []
        for entry in data:
            if not isinstance(entry, dict):
                self.logger.warn("skipping a rule that is not an object: %r", entry)
                continue
            try:
                rule = Rule.from_dict(entry)
                self.evaluator.validate(rule.when)
            except TriggerError as exc:
                self.logger.warn("skipping rule %r: %s", entry.get("name", "?"), exc)
                continue
            rules.append(rule)
        self.rules = rules
        return rules

    # -- evaluation -------------------------------------------------------- #
    def event_matches(self, rule: Rule, event: Event) -> bool:
        """Evaluate one rule against one event.

        Args:
            rule: the rule.
            event: the event.

        Returns:
            True when the condition holds.

        Raises:
            TriggerError: when the condition cannot be evaluated.
        """
        variables = event.variables()
        try:
            return bool(self.evaluator.evaluate(rule.when, variables))
        except TriggerError as exc:
            message = str(exc)
            # Events carry different fields: a rule that mentions 'battery_percent'
            # simply does not apply to a network event, so an undefined name means
            # "no match" rather than a broken rule.
            if "unknown name" in message:
                self.logger.debug("rule '%s' does not apply: %s", rule.name, message)
                return False
            raise TriggerError(f"rule '{rule.name}': {message}") from exc

    def run_actions(self, rule: Rule, event: Event) -> List[str]:
        """Perform a rule's actions.

        Args:
            rule: the rule that fired.
            event: the event that triggered it.

        Returns:
            Human-readable lines describing what was done.
        """
        done: List[str] = []
        variables = event.variables()
        for action in rule.actions:
            kind = str(action.get("type", "")).lower()
            try:
                rendered = {key: render(value, variables)
                            for key, value in action.items()}
            except TriggerError as exc:
                self.logger.warn("rule '%s': %s", rule.name, exc)
                continue
            message = str(rendered.get("message", event.message))
            if kind == "alert":
                done.append(self.action_alert(rule, rendered, message))
            elif kind == "event":
                done.append(self.action_event(rule, message))
            elif kind == "notify":
                done.append(self.action_notify(rendered, message))
            elif kind == "run":
                done.append(self.action_run(rule, rendered))
            elif kind == "unit":
                done.append(self.action_unit(rule, rendered))
            elif kind == "theme":
                done.append(self.action_theme(rule, rendered))
            elif kind == "panic":
                done.append(self.action_panic(rule, rendered))
            elif kind == "report":
                done.append(self.action_report(rule, rendered))
            else:
                self.logger.warn("unknown action type '%s' in rule '%s'", kind, rule.name)
        rule.mark_fired()
        self.fired.append({"rule": rule.name, "event": event.as_dict(),
                           "actions": done, "when": now_iso()})
        return done

    def process(self, events: Sequence[Event]) -> int:
        """Evaluate every event against every rule.

        Args:
            events: the events to process.

        Returns:
            The number of rules that fired.
        """
        fired = 0
        for event in events:
            for rule in self.rules:
                ready, reason = rule.ready()
                if not ready:
                    self.logger.debug("rule '%s' skipped: %s", rule.name, reason)
                    continue
                try:
                    matched = self.event_matches(rule, event)
                except TriggerError as exc:
                    if rule.name not in self.reported:
                        self.logger.error("%s", exc)
                        self.logger.info("fix the condition in %s (rule '%s' stays "
                                         "enabled but will keep failing)",
                                         self.rules_path, rule.name)
                        self.reported.add(rule.name)
                    else:
                        self.logger.debug("%s", exc)
                    continue
                if not matched:
                    continue
                self.logger.ok("rule fired: %s (%s)", rule.name, event.message)
                for line in self.run_actions(rule, event):
                    self.logger.info("  → %s", line)
                fired += 1
        return fired

    # -- actions ----------------------------------------------------------- #
    def action_alert(self, rule: Rule, action: Dict[str, Any], message: str) -> str:
        """Raise an alert through the shared alerting helper.

        Args:
            rule: the rule.
            action: the action definition.
            message: the rendered message.

        Returns:
            A description of what happened.
        """
        severity = str(action.get("severity", "HIGH")).upper()
        if self.dry_run:
            return f"[dry-run] alert {severity}: {message}"
        if self.database is not None:
            try:
                self.database.alert("trigger_engine", severity, rule.name, message)
            except Exception as exc:  # noqa: BLE001 - alerting must never crash a rule
                self.logger.debug("alert insert failed: %s", exc)
        if self.alerts is not None:
            try:
                self.alerts.send(rule.name, message, severity=severity)
            except Exception as exc:  # noqa: BLE001
                self.logger.debug("alert hook failed: %s", exc)
        else:
            self.action_notify({"title": f"ALERT: {rule.name}"}, message)
        return f"alert {severity}: {message}"

    def action_event(self, rule: Rule, message: str) -> str:
        """Record an event in the shared database.

        Args:
            rule: the rule.
            message: the rendered message.

        Returns:
            A description of what happened.
        """
        if self.dry_run:
            return f"[dry-run] event: {message}"
        if self.database is not None:
            try:
                self.database.event("trigger_engine", "automation", message, "INFO",
                                    data={"rule": rule.name})
            except Exception as exc:  # pragma: no cover
                self.logger.debug("event insert failed: %s", exc)
        return f"event: {message}"

    def action_notify(self, action: Dict[str, Any], message: str) -> str:
        """Send a desktop notification when one is possible.

        Args:
            action: the action definition.
            message: the rendered message.

        Returns:
            A description of what happened.
        """
        title = str(action.get("title", "cyberdeck"))
        if self.dry_run:
            return f"[dry-run] notify {title}: {message}"
        if shutil.which("notify-send") and os.environ.get("DISPLAY"):
            try:
                subprocess.run(["notify-send", "-u", "critical", title, message],
                               timeout=10, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return f"notified: {title}"
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.logger.debug("notify-send failed: %s", exc)
        # Fall back to the terminal bell and the log so nothing is silently lost
        self.logger.warn("[notify] %s: %s", title, message)
        return f"logged notification: {title}"

    def action_run(self, rule: Rule, action: Dict[str, Any]) -> str:
        """Run an allow-listed command.

        Args:
            rule: the rule.
            action: the action definition (``command``, ``args``, ``allow_key``).

        Returns:
            A description of what happened.
        """
        command = str(action.get("command", "")).strip()
        args = str(action.get("args", "")).strip()
        allow_key = str(action.get("allow_key", command))
        allowed = self.allowed_commands()
        resolved = allowed.get(allow_key) or allowed.get(command)
        if not resolved:
            return (f"refused to run '{command}': add it to automation.allowed_commands "
                    f"in cyberdeck.conf first")
        try:
            argv = shlex.split(args)
        except ValueError as exc:
            return f"could not parse the arguments for '{command}': {exc}"
        argv = [render(part, {}) if False else part for part in argv]
        full = [resolved] + argv
        if self.dry_run:
            return f"[dry-run] would run: {' '.join(shlex.quote(part) for part in full)}"
        result = run(full, timeout=int(action.get("timeout", 600)))
        return (f"ran {Path(resolved).name} (exit {result.returncode}, "
                f"{len(result.stdout)} bytes of output)")

    def allowed_commands(self) -> Dict[str, str]:
        """Resolve the allow-list of commands that rules may run.

        Returns:
            A mapping of key to executable path.
        """
        raw = self.config.get("automation.allowed_commands", {}) or {}
        mapping: Dict[str, str] = {}
        candidates = {
            "evidence_hasher": self.install_dir / "recon" / "reporting" / "evidence_hasher.py",
            "report_generator": self.install_dir / "recon" / "reporting" / "report_generator.py",
            "theme_switcher": self.install_dir / "aesthetic" / "theme_switcher.sh",
            "hardware_detect": self.install_dir / "utilities" / "hardware_detect.sh",
            "mac_rotator": self.install_dir / "utilities" / "mac_rotator.py",
            "vault": self.install_dir / "utilities" / "encrypted_vault.sh",
            "self_destruct": self.install_dir / "utilities" / "self_destruct.sh",
        }
        if isinstance(raw, dict):
            for key, value in raw.items():
                path = Path(str(value))
                if not path.is_absolute():
                    path = self.install_dir / path
                mapping[str(key)] = str(path)
        else:
            for key in str(raw).split(","):
                key = key.strip()
                if key and key in candidates:
                    mapping[key] = str(candidates[key])
        for key, path in candidates.items():
            mapping.setdefault(key, str(path))
        # Helper scripts and tools are executed with the right interpreter
        for key, path in list(mapping.items()):
            candidate = Path(path)
            if not candidate.exists():
                continue
            if candidate.suffix in (".py", ".sh") and not os.access(candidate, os.X_OK):
                mapping[key] = f"{interpreter_for(candidate)} {candidate}"
        return mapping

    def action_unit(self, rule: Rule, action: Dict[str, Any]) -> str:
        """Start, stop or restart a cyberdeck systemd unit.

        Args:
            rule: the rule.
            action: the action definition (``unit``, ``operation``).

        Returns:
            A description of what happened.
        """
        unit = str(action.get("unit", "")).strip()
        operation = str(action.get("operation", "restart")).strip().lower()
        if not unit.startswith("cyberdeck-"):
            return f"refused: '{unit}' is not a cyberdeck-* unit"
        if operation not in ("start", "stop", "restart"):
            return f"refused: unsupported operation '{operation}'"
        if shutil.which("systemctl") is None:
            return "systemctl is not available on this host"
        if self.dry_run:
            return f"[dry-run] would {operation} {unit}"
        result = run(["systemctl", operation, unit], timeout=60)
        return f"systemctl {operation} {unit} (exit {result.returncode})"

    def action_theme(self, rule: Rule, action: Dict[str, Any]) -> str:
        """Switch the deck theme.

        Args:
            rule: the rule.
            action: the action definition (``theme``).

        Returns:
            A description of what happened.
        """
        theme = str(action.get("theme", "cyberpunk"))
        switcher = self.install_dir / "aesthetic" / "theme_switcher.sh"
        if self.dry_run:
            return f"[dry-run] would switch the theme to {theme}"
        if not switcher.is_file():
            return f"theme switcher not installed at {switcher}"
        result = run(["bash", str(switcher), "--set", theme], timeout=60)
        return f"theme → {theme} (exit {result.returncode})"

    def action_panic(self, rule: Rule, action: Dict[str, Any]) -> str:
        """Run the panic button.

        Args:
            rule: the rule.
            action: the action definition (``level``).

        Returns:
            A description of what happened.
        """
        level = str(action.get("level", "soft")).lstrip("-")
        script = self.install_dir / "utilities" / "self_destruct.sh"
        if self.dry_run:
            return f"[dry-run] would run self-destruct --{level}"
        if not script.is_file():
            return f"self-destruct not installed at {script}"
        if not self.assume_yes:
            self.logger.warn("rule '%s' wants to run the panic button - refusing "
                             "without --yes", rule.name)
            return "panic action needs --yes on the trigger engine command line"
        result = run(["bash", str(script), f"--{level}", "--yes"], timeout=900)
        return f"self-destruct --{level} (exit {result.returncode})"

    def action_report(self, rule: Rule, action: Dict[str, Any]) -> str:
        """Generate a report for an engagement directory.

        Args:
            rule: the rule.
            action: the action definition (``engagement``).

        Returns:
            A description of what happened.
        """
        engagement = str(action.get("engagement", "")).strip()
        generator = self.install_dir / "recon" / "reporting" / "report_generator.py"
        if not engagement:
            return "report action needs an 'engagement' path"
        if self.dry_run:
            return f"[dry-run] would generate a report for {engagement}"
        argv = [sys.executable, str(generator), engagement]
        result = run(argv, timeout=600)
        return f"report for {engagement} (exit {result.returncode})"

    # -- state ------------------------------------------------------------- #
    def save_state(self) -> Optional[Path]:
        """Persist the counters and the fire log.

        Returns:
            The path written, or ``None`` when nothing could be written.
        """
        state_dir = self.install_dir / "state"
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            path = state_dir / "triggers_state.json"
            path.write_text(json.dumps({
                "saved": now_iso(),
                "rules": [rule.as_dict() for rule in self.rules],
                "fired": self.fired[-200:],
            }, indent=2) + "\n")
            try:
                path.chmod(0o600)
            except OSError:  # pragma: no cover
                pass
            return path
        except OSError as exc:
            self.logger.warn("could not save the trigger state: %s", exc)
            return None

    def close(self) -> None:
        """Close the database handle."""
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # pragma: no cover
                pass


def interpreter_for(path: Path) -> str:
    """Return the interpreter used to launch a script.

    Args:
        path: the script path.

    Returns:
        The interpreter command.
    """
    if path.suffix == ".py":
        return sys.executable
    return "bash"


def render(template: Any, variables: Dict[str, Any]) -> Any:
    """Render ``{name}`` placeholders in an action value.

    Args:
        template: the value from the rule definition.
        variables: the event variables.

    Returns:
        The rendered value (non-strings pass through unchanged).

    Raises:
        TriggerError: when the placeholder references an unknown name.
    """
    if not isinstance(template, str):
        return template
    if "{" not in template:
        return template
    out: List[str] = []
    index = 0
    while index < len(template):
        character = template[index]
        if character == "{":
            end = template.find("}", index)
            if end == -1:
                out.append(template[index:])
                break
            name = template[index + 1:end].strip()
            if name and name not in variables:
                raise TriggerError(f"unknown placeholder '{name}' in the action")
            out.append(str(variables.get(name, "")))
            index = end + 1
            continue
        out.append(character)
        index += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="triggers.py",
        description="Event driven automation rules for the cyberdeck",
        epilog="rules live in data/triggers.json; conditions are sandboxed")
    parser.add_argument("--version", action="version", version=f"triggers {VERSION}")
    parser.add_argument("--watch", action="store_true", help="run as a daemon")
    parser.add_argument("--once", action="store_true", help="evaluate once and exit")
    parser.add_argument("--interval", type=int, default=5, help="poll interval (default: 5s)")
    parser.add_argument("--watch-paths", default="",
                        help="extra comma-separated paths to watch for new files")
    parser.add_argument("--rules", type=Path, default=None, help="alternative rules file")
    parser.add_argument("--reset-rules", action="store_true",
                        help="rewrite data/triggers.json from the built-in defaults")
    parser.add_argument("--list", action="store_true", help="list the loaded rules")
    parser.add_argument("--test", default="", help="evaluate an expression against a test event")
    parser.add_argument("--with", dest="variables", action="append", default=[],
                        help="key=value pairs for --test (repeatable)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="print what would happen without doing it")
    parser.add_argument("--yes", action="store_true",
                        help="allow the panic action without asking")
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the trigger engine.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("triggers", level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("trigger engine", f"v{VERSION} · event driven automation")

    engine = TriggerEngine(config, logger, rules_path=args.rules)
    engine.dry_run = args.dry_run
    engine.assume_yes = args.yes

    if args.reset_rules:
        engine.ensure_rules_file(force=True)
        logger.ok("rules reset to the built-in defaults")
        if not (args.list or args.watch or args.once):
            return 0

    try:
        rules = engine.load_rules()
    except TriggerError as exc:
        logger.error("%s", exc)
        return 1

    if args.test:
        variables = {"kind": "test", "source": "cli", "message": "test event"}
        for pair in args.variables:
            key, _, value = pair.partition("=")
            if not key:
                continue
            if value.lower() in ("true", "false"):
                variables[key] = value.lower() == "true"
                continue
            try:
                variables[key] = int(value)
            except ValueError:
                try:
                    variables[key] = float(value)
                except ValueError:
                    variables[key] = value
        try:
            result = engine.evaluator.evaluate(args.test, variables)
        except TriggerError as exc:
            logger.error("%s", exc)
            return 1
        print(json.dumps({"expression": args.test, "variables": variables,
                          "result": bool(result)}, indent=2)
              if args.json else f"{args.test} → {bool(result)}")
        return 0 if result else 10

    if args.list:
        print()
        print(f"  {'RULE':<30}{'COOLDOWN':>9}{'MAX/H':>7}  {'ENABLED':<8}CONDITION")
        print("  " + "─" * 96)
        for rule in rules:
            print(f"  {rule.name[:28]:<30}{rule.cooldown_s:>8}s{rule.max_per_hour:>7}  "
                  f"{'yes' if rule.enabled else 'no':<8}{rule.when[:44]}")
            if rule.description:
                print(f"    {colour(rule.description[:90], 'dim')}")
        print()
        if args.json:
            print(json.dumps([rule.as_dict() for rule in rules], indent=2))
        return 0

    if not (args.watch or args.once):
        logger.info("nothing to do - use --once to evaluate or --watch to run as a daemon")
        logger.info("see the rules with --list")
        return 0

    watch_paths: List[Path] = []
    configured = args.watch_paths or str(config.get("automation.watch_paths", ""))
    for entry in str(configured).replace(";", ",").split(","):
        entry = entry.strip()
        if entry:
            watch_paths.append(Path(entry))
    if not watch_paths:
        watch_paths = [engine.install_dir / "captures", engine.install_dir / "reports"]
    logger.info("%d rule(s) loaded, watching %d path(s)", len(rules), len(watch_paths))

    db_watcher = DatabaseWatcher(engine.install_dir, logger)
    sys_watcher = SystemWatcher(engine.install_dir, logger)
    file_watcher = FileWatcher(watch_paths, logger)
    running = True

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal running
        logger.info("stopping the trigger engine")
        running = False

    for name in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, name), stop)
        except (ValueError, OSError):  # pragma: no cover
            pass

    total = 0
    try:
        while running:
            events = []
            events.extend(db_watcher.poll())
            events.extend(sys_watcher.sample())
            events.extend(file_watcher.poll())
            if events:
                fired = engine.process(events)
                total += fired
                if args.json:
                    pass
                elif events and not fired and logger.level_name == "DEBUG":
                    logger.debug("%d event(s), no rule matched", len(events))
            if args.once and not args.watch:
                break
            time.sleep(max(1, args.interval))
    finally:
        state = engine.save_state()
        engine.close()

    if args.json:
        print(json.dumps({"rules": len(rules), "fired": total,
                          "log": engine.fired}, indent=2))
    else:
        logger.ok("finished: %d rule(s) fired", total)
        if state:
            logger.info("state written to %s", state)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
