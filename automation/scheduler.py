#!/usr/bin/env python3
"""
automation/scheduler.py - the deck's own task scheduler.
========================================================

Description
-----------
Runs recurring jobs for the platform without hiding them in crontab: the task
list lives in ``state/schedule.json`` (seeded with useful defaults on first
run), every run is timed and logged, and the results land in the shared events
database so the HUD can show what happened and when.

Features
--------
* interval schedules (``15m``, ``2h``, ``1d``), daily wall-clock schedules
  (``at: 03:30``) and one-shot timestamps (``once_at``)
* capability gating: a task can declare ``requires: wifi,sdr,gpio,root`` and is
  skipped, visibly, when the hardware or privilege is missing
* catch-up policy: a task missed while the deck was asleep can either run
  immediately (``catchup: true``) or wait for its next slot
* retries with exponential backoff, per-task timeouts and a single-run lock so
  a slow task never overlaps itself
* stdout/stderr per task in ``logs/schedule_<task>.log`` and a rotation of the
  recent run history in ``state/schedule_state.json``
* graceful shutdown: SIGTERM is forwarded to the running child

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Usage
-----
    ./scheduler.py --list
    ./scheduler.py --daemon                     # foreground scheduler loop
    ./scheduler.py --run now                    # run one task immediately
    ./scheduler.py --add recon --command "bin/cdeck scan 10.0.0.0/24" --every 30m
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
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
        Config,
        Database,
        Hardware,
        Logger,
        colour,
        human_duration,
        is_root,
        now_iso,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: Tasks written to state/schedule.json the first time the scheduler runs.
#: Commands are relative to the install directory and run through shlex, never
#: through a shell.
DEFAULT_TASKS: List[Dict[str, Any]] = [
    {
        "name": "hardware-refresh",
        "description": "Re-detect the hardware so the HUD shows the current truth",
        "command": "utilities/hardware_detect.sh --write",
        "every": "1h",
        "timeout_s": 120,
        "tags": ["housekeeping"],
    },
    {
        "name": "evidence-verify",
        "description": "Verify the chain of custody of everything under captures/",
        "command": "recon/reporting/evidence_hasher.py verify captures",
        "every": "6h",
        "timeout_s": 900,
        "tags": ["evidence"],
    },
    {
        "name": "vault-verify",
        "description": "Check the encrypted vault against its manifest",
        "command": "utilities/encrypted_vault.sh --verify",
        "every": "12h",
        "timeout_s": 300,
        "requires": "root",
        "tags": ["evidence"],
    },
    {
        "name": "report-refresh",
        "description": "Regenerate the Markdown/HTML report for each engagement",
        "command": "recon/reporting/report_generator.py --all-engagements",
        "every": "1d",
        "at": "06:30",
        "timeout_s": 1800,
        "tags": ["reporting"],
    },
    {
        "name": "database-vacuum",
        "description": "Compact the SQLite databases and refresh the OUI lookups",
        "command": "bin/cdeck doctor --vacuum",
        "every": "7d",
        "at": "04:00",
        "timeout_s": 900,
        "tags": ["housekeeping"],
    },
    {
        "name": "wordlist-refresh",
        "description": "Update the wordlists when there is connectivity",
        "command": "data/wordlists/download_wordlists.sh --quiet",
        "every": "7d",
        "at": "03:00",
        "timeout_s": 3600,
        "requires": "network",
        "tags": ["recon"],
    },
    {
        "name": "selftest",
        "description": "Run the installation self-test and record the result",
        "command": "tests/test_installation.sh --quiet",
        "every": "1d",
        "at": "05:00",
        "timeout_s": 600,
        "tags": ["health"],
    },
]

#: Interval suffixes used by ``every``
INTERVAL_UNITS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}


class ScheduleError(Exception):
    """Raised when a task definition or the task file is invalid."""


def parse_interval(text: str) -> int:
    """Parse an interval such as ``15m``, ``2h`` or ``1d`` into seconds.

    Args:
        text: the interval string.

    Returns:
        The interval in seconds.

    Raises:
        ScheduleError: when the interval cannot be parsed.
    """
    text = str(text).strip().lower()
    if not text:
        raise ScheduleError("empty interval")
    if text.isdigit():
        return int(text)
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([a-z]+)", text)
    if not match:
        raise ScheduleError(f"cannot parse the interval '{text}'")
    value = float(match.group(1))
    unit = match.group(2)
    if unit not in INTERVAL_UNITS:
        raise ScheduleError(f"unknown interval unit '{unit}'")
    return int(value * INTERVAL_UNITS[unit])


def describe_interval(seconds: int) -> str:
    """Return a compact description of an interval.

    Args:
        seconds: the interval in seconds.

    Returns:
        A human string such as ``15m`` or ``2h30m``.
    """
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


@dataclass
class Task:
    """One scheduled task."""

    name: str
    command: str
    description: str = ""
    every_s: Optional[int] = None
    at: str = ""
    once_at: str = ""
    enabled: bool = True
    timeout_s: int = 900
    catchup: bool = True
    retries: int = 0
    requires: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cwd: str = ""
    last_run: Optional[str] = None
    last_status: str = ""
    last_duration_s: float = 0.0
    last_exit: Optional[int] = None
    next_run: Optional[str] = None
    runs: int = 0
    failures: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        """Build a task from its JSON representation.

        Args:
            data: the dictionary from schedule.json.

        Returns:
            The task.

        Raises:
            ScheduleError: when the task is invalid.
        """
        name = str(data.get("name", "")).strip()
        command = str(data.get("command", "")).strip()
        if not name:
            raise ScheduleError(f"task without a name: {data}")
        if not command:
            raise ScheduleError(f"task '{name}' has no command")
        every_s = None
        if data.get("every"):
            every_s = parse_interval(str(data["every"]))
        at = str(data.get("at", "")).strip()
        if at and not re.fullmatch(r"\d{1,2}:\d{2}", at):
            raise ScheduleError(f"task '{name}': 'at' must look like 03:30")
        once_at = str(data.get("once_at", "")).strip()
        if once_at:
            try:
                datetime.fromisoformat(once_at.replace("Z", ""))
            except ValueError as exc:
                raise ScheduleError(f"task '{name}': bad once_at timestamp: {exc}") from exc
        if not (every_s or at or once_at):
            raise ScheduleError(f"task '{name}' needs 'every', 'at' or 'once_at'")
        requires = data.get("requires", [])
        if isinstance(requires, str):
            requires = [part.strip() for part in requires.split(",") if part.strip()]
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [part.strip() for part in tags.split(",") if part.strip()]
        return cls(
            name=name,
            command=command,
            description=str(data.get("description", "")),
            every_s=every_s,
            at=at,
            once_at=once_at,
            enabled=bool(data.get("enabled", True)),
            timeout_s=int(data.get("timeout_s", 900)),
            catchup=bool(data.get("catchup", True)),
            retries=int(data.get("retries", 0)),
            requires=list(requires),
            tags=list(tags),
            cwd=str(data.get("cwd", "")),
            last_run=data.get("last_run"),
            last_status=str(data.get("last_status", "")),
            last_duration_s=float(data.get("last_duration_s", 0.0) or 0.0),
            last_exit=data.get("last_exit"),
            runs=int(data.get("runs", 0) or 0),
            failures=int(data.get("failures", 0) or 0),
            history=list(data.get("history", []) or []),
        )

    # -- timing ------------------------------------------------------------ #
    def due_at(self, reference: Optional[datetime] = None) -> Optional[datetime]:
        """Return the next time this task should run.

        Args:
            reference: the reference moment (defaults to now).

        Returns:
            The next due time, or ``None`` when the task is one-shot and done.
        """
        reference = reference or datetime.now().astimezone()
        if self.once_at:
            try:
                target = datetime.fromisoformat(self.once_at.replace("Z", ""))
            except ValueError:
                return None
            if target.tzinfo is None:
                target = target.astimezone()
            return target
        if self.at:
            hour, minute = (int(part) for part in self.at.split(":"))
            candidate = reference.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if candidate <= reference:
                candidate += timedelta(days=1)
            if self.every_s and self.last_run:
                try:
                    previous = datetime.fromisoformat(self.last_run)
                except ValueError:
                    previous = None
                if previous is not None and previous.tzinfo is None:
                    previous = previous.astimezone()
                interval_candidate = previous + timedelta(seconds=self.every_s) if previous \
                    else None
                if interval_candidate and interval_candidate < candidate \
                        and interval_candidate > reference:
                    return interval_candidate
            return candidate
        if self.every_s:
            if not self.last_run:
                return reference
            try:
                previous = datetime.fromisoformat(self.last_run)
            except ValueError:
                return reference
            if previous.tzinfo is None:
                previous = previous.astimezone()
            candidate = previous + timedelta(seconds=self.every_s)
            if candidate < reference and not self.catchup:
                missed = int((reference - candidate).total_seconds() // self.every_s) + 1
                candidate += timedelta(seconds=self.every_s * missed)
            return candidate
        return None

    def is_due(self, reference: Optional[datetime] = None) -> bool:
        """Return True when the task should run now.

        Args:
            reference: the reference moment.

        Returns:
            True when due.
        """
        if not self.enabled:
            return False
        if self.once_at and self.last_run:
            return False
        due = self.due_at(reference)
        if due is None:
            return False
        return due <= (reference or datetime.now().astimezone())

    def refresh_next_run(self, reference: Optional[datetime] = None) -> None:
        """Update the cached ``next_run`` value.

        Args:
            reference: the reference moment.
        """
        reference = reference or datetime.now().astimezone()
        if self.once_at and self.last_run:
            self.next_run = None
            return
        due = self.due_at(reference)
        if due is None:
            self.next_run = None
            return
        if due <= reference and self.every_s:
            due = reference
        self.next_run = due.isoformat()

    # -- capability gating -------------------------------------------------- #
    def missing_requirements(self, config: Config, install_dir: Path) -> List[str]:
        """Return the requirements this host does not satisfy.

        Args:
            config: the loaded configuration.
            install_dir: the install directory (for script checks).

        Returns:
            A list of unmet requirement names.
        """
        unmet: List[str] = []
        for requirement in self.requires:
            key = requirement.strip().lower()
            if key == "root":
                if not is_root():
                    unmet.append("root")
            elif key == "network":
                if not have_network():
                    unmet.append("network")
            elif key == "wifi":
                if not Hardware.wifi_interfaces():
                    unmet.append("wifi")
            elif key == "monitor":
                if not Hardware.monitor_capable():
                    unmet.append("monitor")
            elif key == "sdr":
                if not Hardware.sdr_devices():
                    unmet.append("sdr")
            elif key == "proxmark":
                if not Hardware.proxmark():
                    unmet.append("proxmark")
            elif key == "gpio":
                if not Hardware.gpio_available():
                    unmet.append("gpio")
            elif key == "gps":
                if not Hardware.gps_device():
                    unmet.append("gps")
            else:
                unmet.append(f"unknown:{key}")
        return unmet

    def resolve_command(self, install_dir: Path) -> Optional[List[str]]:
        """Turn the stored command into an argument vector.

        Relative commands are resolved against the install directory first, then
        against ``PATH``. Scripts that are not executable are run through their
        interpreter so a missing ``chmod +x`` cannot silently break a task.

        Args:
            install_dir: the install directory used for relative paths.

        Returns:
            The argument vector, or ``None`` when the executable is missing.
        """
        try:
            argv = shlex.split(self.command)
        except ValueError:
            return None
        if not argv:
            return None
        argv = list(argv)
        candidate = Path(argv[0])
        if not candidate.is_absolute():
            candidate = install_dir / candidate
        if candidate.exists():
            argv[0] = str(candidate)
            if candidate.suffix in (".py", ".sh") and not os.access(candidate, os.X_OK):
                interpreter = sys.executable if candidate.suffix == ".py" else "bash"
                argv.insert(0, interpreter)
            return argv
        if Path(argv[0]).is_absolute() or "/" in argv[0]:
            # An explicit path that does not exist is a configuration error
            return None
        if shutil.which(argv[0]) is None:
            return None
        return argv

    def as_dict(self) -> Dict[str, Any]:
        """Return the task as a plain dictionary.

        Returns:
            The dictionary.
        """
        return {
            "name": self.name,
            "description": self.description,
            "command": self.command,
            "every": describe_interval(self.every_s) if self.every_s else "",
            "at": self.at,
            "once_at": self.once_at,
            "enabled": self.enabled,
            "timeout_s": self.timeout_s,
            "catchup": self.catchup,
            "retries": self.retries,
            "requires": self.requires,
            "tags": self.tags,
            "cwd": self.cwd,
            "last_run": self.last_run,
            "last_status": self.last_status,
            "last_duration_s": round(self.last_duration_s, 2),
            "last_exit": self.last_exit,
            "next_run": self.next_run,
            "runs": self.runs,
            "failures": self.failures,
            "history": self.history[-10:],
        }


def have_network() -> bool:
    """Cheap connectivity check that does not need a DNS lookup.

    Returns:
        True when a default route exists and a TCP connect succeeds.
    """
    import socket

    for host, port in (("1.1.1.1", 53), ("9.9.9.9", 53)):
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True
        except OSError:
            continue
    return False


class Scheduler:
    """Loads, schedules and runs the deck's recurring tasks.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
        path: alternative task file.
    """

    def __init__(self, config: Config, logger: Logger, path: Optional[Path] = None) -> None:
        """Create the scheduler."""
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                               "/opt/cyberdeck-arsenal")))
        self.path = path or (self.install_dir / "state" / "schedule.json")
        self.state_path = self.install_dir / "state" / "schedule_state.json"
        self.log_dir = self.install_dir / "logs"
        self.tasks: List[Task] = []
        self.dry_run = False
        self.current: Optional[subprocess.Popen] = None
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)

    # -- persistence -------------------------------------------------------- #
    def ensure_file(self, force: bool = False) -> Path:
        """Write the default task file when it is missing.

        Args:
            force: overwrite an existing file with the defaults.

        Returns:
            The task file path.
        """
        if self.path.is_file() and not force:
            return self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"tasks": DEFAULT_TASKS}, indent=2) + "\n")
        self.logger.info("default schedule written to %s", self.path)
        return self.path

    def load(self) -> List[Task]:
        """Load the tasks from disk.

        Returns:
            The loaded tasks.

        Raises:
            ScheduleError: when the file is invalid.
        """
        path = self.ensure_file()
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ScheduleError(f"cannot read {path}: {exc}") from exc
        entries = data.get("tasks", []) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            raise ScheduleError(f"{path} must contain a list of tasks")
        tasks: List[Task] = []
        for entry in entries:
            if not isinstance(entry, dict):
                self.logger.warn("skipping a task that is not an object: %r", entry)
                continue
            try:
                task = Task.from_dict(entry)
            except ScheduleError as exc:
                self.logger.warn("%s", exc)
                continue
            task.refresh_next_run()
            tasks.append(task)
        self.tasks = tasks
        return tasks

    def save(self) -> Optional[Path]:
        """Persist the task list and the run history.

        Returns:
            The path written, or ``None`` on failure.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(
                {"version": VERSION, "updated": now_iso(),
                 "tasks": [task.as_dict() for task in self.tasks]}, indent=2) + "\n")
        except OSError as exc:
            self.logger.warn("could not write the schedule: %s", exc)
            return None
        history = [entry for task in self.tasks for entry in task.history]
        history.sort(key=lambda entry: entry.get("started", ""))
        try:
            self.state_path.write_text(json.dumps({
                "saved": now_iso(),
                "tasks": len(self.tasks),
                "history": history[-200:],
            }, indent=2) + "\n")
            try:
                self.state_path.chmod(0o600)
            except OSError:  # pragma: no cover
                pass
        except OSError as exc:
            self.logger.debug("could not write the run history: %s", exc)
        return self.path

    def find(self, name: str) -> Optional[Task]:
        """Return a task by name.

        Args:
            name: the task name.

        Returns:
            The task, or ``None``.
        """
        for task in self.tasks:
            if task.name == name:
                return task
        return None

    # -- running ------------------------------------------------------------ #
    def run_task(self, task: Task, reason: str = "schedule") -> bool:
        """Run a task, honouring the timeout, retries and capability gates.

        Args:
            task: the task to run.
            reason: why it is running (for the log).

        Returns:
            True when the task succeeded.
        """
        unmet = task.missing_requirements(self.config, self.install_dir)
        if unmet:
            self.logger.warn("task '%s' skipped - this host has no %s",
                             task.name, ", ".join(unmet))
            task.last_status = f"skipped (missing {','.join(unmet)})"
            self.record_event(task, "WARNING",
                              f"skipped: missing {', '.join(unmet)}", 0.0, None)
            self.save()
            return False

        argv = task.resolve_command(self.install_dir)
        if argv is None:
            self.logger.error("task '%s': cannot resolve the command '%s'",
                              task.name, task.command)
            task.last_status = "unresolved command"
            self.record_event(task, "WARNING", "unresolved command", 0.0, None)
            self.save()
            return False

        attempts = max(1, task.retries + 1)
        for attempt in range(1, attempts + 1):
            if self.dry_run:
                self.logger.info("[dry-run] would run '%s': %s",
                                 task.name, " ".join(shlex.quote(part) for part in argv))
                return True
            self.logger.info("running '%s' (%s, attempt %d/%d): %s",
                             task.name, reason, attempt, attempts,
                             " ".join(shlex.quote(part) for part in argv))
            started = time.time()
            log_path = self.log_dir / f"schedule_{task.name}.log"
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
                handle = log_path.open("a")
            except OSError:
                handle = None
            try:
                self.current = subprocess.Popen(
                    argv, cwd=str(task.cwd) if task.cwd else str(self.install_dir),
                    stdout=handle or subprocess.DEVNULL,
                    stderr=subprocess.STDOUT if handle else subprocess.DEVNULL,
                    start_new_session=True)
                try:
                    exit_code = self.current.wait(timeout=task.timeout_s)
                except subprocess.TimeoutExpired:
                    self.logger.error("task '%s' exceeded its %ss timeout - killing it",
                                      task.name, task.timeout_s)
                    self.current.kill()
                    exit_code = self.current.wait(timeout=15)
                    if handle:
                        handle.write(f"\n[cyberdeck] killed after {task.timeout_s}s timeout\n")
                finally:
                    self.current = None
            except OSError as exc:
                self.logger.error("task '%s' could not start: %s", task.name, exc)
                if handle:
                    handle.close()
                task.last_status = f"failed to start: {exc}"
                self.record_event(task, "ERROR", f"failed to start: {exc}", 0.0, None)
                self.save()
                return False
            finally:
                if handle:
                    handle.close()

            duration = time.time() - started
            task.runs += 1
            task.last_run = now_iso()
            task.last_duration_s = duration
            task.last_exit = exit_code
            entry = {
                "started": task.last_run,
                "reason": reason,
                "duration_s": round(duration, 2),
                "exit": exit_code,
                "attempt": attempt,
            }
            task.history.append(entry)
            task.history = task.history[-50:]

            if exit_code == 0:
                task.last_status = "ok"
                self.logger.ok("task '%s' finished in %.1fs", task.name, duration)
                self.record_event(task, "INFO",
                                  f"completed in {human_duration(duration)}", duration, 0)
                task.refresh_next_run()
                self.save()
                return True

            task.failures += 1
            task.last_status = f"exit {exit_code}"
            self.logger.error("task '%s' failed with exit code %s", task.name, exit_code)
            if attempt < attempts:
                backoff = min(60, 2 ** attempt)
                self.logger.info("retrying '%s' in %ss", task.name, backoff)
                time.sleep(backoff)
            else:
                self.record_event(task, "ERROR",
                                  f"failed with exit code {exit_code}", duration, exit_code)
        task.refresh_next_run()
        self.save()
        return False

    def record_event(self, task: Task, severity: str, message: str, duration: float,
                     exit_code: Optional[int]) -> None:
        """Record a task result in the shared events database.

        Args:
            task: the task.
            severity: INFO/WARNING/ERROR.
            message: the outcome text.
            duration: how long it ran.
            exit_code: the process exit code.
        """
        if self.database is None:
            return
        try:
            self.database.event("scheduler", "automation", f"{task.name}: {message}",
                                severity,
                                data={"task": task.name, "duration_s": round(duration, 2),
                                      "exit": exit_code, "command": task.command})
        except Exception as exc:  # pragma: no cover
            self.logger.debug("event insert failed: %s", exc)

    def due_tasks(self) -> List[Task]:
        """Return the tasks that are due now.

        Returns:
            The due tasks.
        """
        now = datetime.now().astimezone()
        return [task for task in self.tasks if task.is_due(now)]

    # -- management --------------------------------------------------------- #
    def add_task(self, name: str, command: str, every: str = "", at: str = "",
                 description: str = "", requires: str = "", retries: int = 0) -> Task:
        """Add or replace a task.

        Args:
            name: task name.
            command: the command line.
            every: interval string.
            at: daily wall-clock time.
            description: free text.
            requires: comma-separated requirements.
            retries: retry count.

        Returns:
            The stored task.

        Raises:
            ScheduleError: when the definition is invalid.
        """
        entry: Dict[str, Any] = {
            "name": name, "command": command, "description": description,
            "retries": retries,
        }
        if every:
            entry["every"] = every
        if at:
            entry["at"] = at
        if requires:
            entry["requires"] = requires
        task = Task.from_dict(entry)
        self.tasks = [existing for existing in self.tasks if existing.name != name]
        self.tasks.append(task)
        self.tasks.sort(key=lambda item: item.name)
        task.refresh_next_run()
        self.save()
        return task

    def remove_task(self, name: str) -> bool:
        """Remove a task by name.

        Args:
            name: the task name.

        Returns:
            True when something was removed.
        """
        before = len(self.tasks)
        self.tasks = [task for task in self.tasks if task.name != name]
        if len(self.tasks) == before:
            return False
        self.save()
        return True

    def set_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a task.

        Args:
            name: the task name.
            enabled: the new state.

        Returns:
            True when the task exists.
        """
        task = self.find(name)
        if task is None:
            return False
        task.enabled = enabled
        task.refresh_next_run()
        self.save()
        return True

    def list_tasks(self) -> int:
        """Print the task table.

        Returns:
            Process exit code.
        """
        if not self.tasks:
            self.logger.info("no tasks are defined - run with --reset to load the defaults")
            return 3
        print()
        print(f"  {'TASK':<20}{'SCHEDULE':<14}{'NEXT RUN':<21}{'LAST':<12}"
              f"{'RUNS':>5}{'FAIL':>6}  DESCRIPTION")
        print("  " + "─" * 104)
        for task in sorted(self.tasks, key=lambda item: item.name):
            schedule = describe_interval(task.every_s) if task.every_s else ""
            if task.at:
                schedule = f"daily {task.at}"
            if task.once_at:
                schedule = "once"
            when = (task.next_run or "—")[:19] if task.next_run else "—"
            print(f"  {(task.name + ('' if task.enabled else ' (off)'))[:18]:<20}"
                  f"{schedule:<14}{when:<21}{(task.last_status or '—')[:10]:<12}"
                  f"{task.runs:>5}{task.failures:>6}  {task.description[:34]}")
        print()
        return 0

    def close(self) -> None:
        """Close the database handle."""
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # pragma: no cover
                pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="scheduler.py",
        description="Recurring task scheduler for the cyberdeck",
        epilog="tasks live in state/schedule.json; see --list")
    parser.add_argument("--version", action="version", version=f"scheduler {VERSION}")
    parser.add_argument("--file", type=Path, default=None, help="alternative task file")
    parser.add_argument("--list", action="store_true", help="list the tasks")
    parser.add_argument("--daemon", action="store_true", help="run the scheduler loop")
    parser.add_argument("--once", action="store_true", help="run everything due, then exit")
    parser.add_argument("--interval", type=int, default=30, help="loop tick interval (default 30s)")
    parser.add_argument("--run", metavar="NAME", default="", help="run one task now")
    parser.add_argument("--reset", action="store_true", help="rewrite the default task list")
    parser.add_argument("--add", metavar="NAME", default="", help="add a task")
    parser.add_argument("--command", default="", help="command for --add")
    parser.add_argument("--every", default="", help="interval for --add (15m, 2h, 1d)")
    parser.add_argument("--at", default="", help="daily time for --add (03:30)")
    parser.add_argument("--requires", default="", help="requirements for --add (wifi,sdr,root)")
    parser.add_argument("--retries", type=int, default=0, help="retries for --add")
    parser.add_argument("--description", default="", help="description for --add")
    parser.add_argument("--remove", metavar="NAME", default="", help="remove a task")
    parser.add_argument("--enable", metavar="NAME", default="", help="enable a task")
    parser.add_argument("--disable", metavar="NAME", default="", help="disable a task")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="show what would run without running it")
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the scheduler.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("scheduler", level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("task scheduler", f"v{VERSION} · recurring automation")

    scheduler = Scheduler(config, logger, path=args.file)
    scheduler.dry_run = args.dry_run

    if args.reset:
        scheduler.ensure_file(force=True)
        logger.ok("schedule reset to the defaults")
        if not (args.list or args.daemon or args.once):
            return 0

    try:
        scheduler.load()
    except ScheduleError as exc:
        logger.error("%s", exc)
        return 1

    if args.add:
        if not args.command:
            logger.error("--add needs --command")
            return 2
        if not (args.every or args.at):
            logger.error("--add needs --every or --at")
            return 2
        try:
            task = scheduler.add_task(args.add, args.command, every=args.every,
                                      at=args.at, description=args.description,
                                      requires=args.requires, retries=args.retries)
        except ScheduleError as exc:
            logger.error("%s", exc)
            return 2
        logger.ok("task '%s' stored in %s", task.name, scheduler.path)
        return 0

    if args.remove:
        if scheduler.remove_task(args.remove):
            logger.ok("task '%s' removed", args.remove)
            return 0
        logger.error("no such task: %s", args.remove)
        return 1

    if args.enable or args.disable:
        name = args.enable or args.disable
        if scheduler.set_enabled(name, bool(args.enable)):
            logger.ok("task '%s' %s", name, "enabled" if args.enable else "disabled")
            return 0
        logger.error("no such task: %s", name)
        return 1

    if args.list:
        scheduler.list_tasks()
        if args.json:
            print(json.dumps([task.as_dict() for task in scheduler.tasks], indent=2))
        return 0

    if args.run:
        task = scheduler.find(args.run) if args.run != "now" else None
        if args.run != "now" and task is None:
            logger.error("no such task: %s", args.run)
            return 1
        targets = [task] if task is not None else scheduler.due_tasks()
        if not targets:
            logger.info("nothing is due right now")
            return 0
        failures = 0
        for target in targets:
            if not scheduler.run_task(target, reason="manual"):
                failures += 1
        logger.ok("ran %d task(s), %d failure(s)", len(targets), failures)
        scheduler.close()
        return 1 if failures else 0

    if not (args.daemon or args.once):
        logger.info("nothing to do - use --list, --run NAME, --once or --daemon")
        return 0

    running = True

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal running
        logger.info("stopping the scheduler")
        running = False
        if scheduler.current is not None:
            try:
                scheduler.current.terminate()
            except OSError:  # pragma: no cover
                pass

    for name in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, name), stop)
        except (ValueError, OSError):  # pragma: no cover
            pass

    logger.info("%d task(s) loaded from %s", len(scheduler.tasks), scheduler.path)
    executed = 0
    try:
        while running:
            due = scheduler.due_tasks()
            for task in due:
                if not running:
                    break
                executed += 1
                scheduler.run_task(task, reason="schedule")
            if args.once and not args.daemon:
                break
            scheduler.save()
            for _ in range(max(1, args.interval)):
                if not running:
                    break
                time.sleep(1)
    finally:
        scheduler.save()
        scheduler.close()

    if args.json:
        print(json.dumps({"executed": executed,
                          "tasks": [task.as_dict() for task in scheduler.tasks]},
                         indent=2))
    else:
        logger.ok("scheduler stopped after %d run(s)", executed)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
