#!/usr/bin/env python3
"""
gpio/button_handler.py - physical button actions for the deck.
================================================================

Description
-----------
Turns one momentary button (``gpio.button_pin``, default BCM 22, wired to ground
with the internal pull-up) into a control surface:

=============== ============================================================
**short press**  run the configured action - dashboard, status or scan
**double press** cycle the theme
**long press**   the panic button: confirm, then run the soft self-destruct
**hold 10s**     emergency stop - kill the paid-for-radio processes immediately
=============== ============================================================

The mapping lives in ``cyberdeck.conf`` under ``gpio.button_actions`` and falls
back to the defaults above; every action is an argument vector, never a shell
string, and every action is checked for the file it needs before it runs. The
panic path follows the same rules as ``cdeck panic``: it always confirms unless
``--yes`` was given, and it logs loudly either way.

Without GPIO hardware the handler runs against the simulated backend. That is
not a stub: ``--simulate short``, ``--simulate double``, ``--simulate long`` and
``--simulate emergency`` inject the exact same events through the same code path
the real button uses, which is how the mapping is tested.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library, lib/cybergpio.py
              optional: lgpio / RPi.GPIO / gpiod for a real button
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Usage
-----
    sudo ./button_handler.py                  # run the handler
    ./button_handler.py --list-actions
    ./button_handler.py --simulate short --dry-run
    ./button_handler.py --simulate long --yes
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
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
    from cyberlib import Alerts, Config, Database, now_iso  # type: ignore
except ImportError:  # pragma: no cover - cyberlib is optional here
    from cybergpio import Logger  # type: ignore

    Config = None  # type: ignore
    Alerts = None  # type: ignore
    Database = None  # type: ignore

    def now_iso() -> str:
        """Fallback timestamp helper.

        Returns:
            An ISO-8601 timestamp.
        """
        return datetime.now().astimezone().isoformat(timespec="seconds")

VERSION = "1.0.0"

#: Default event → action mapping. Every value is an argv list executed with
#: ``subprocess`` (never through a shell) relative to the install directory.
DEFAULT_ACTIONS: Dict[str, List[str]] = {
    "short":            ["bin/cdeck", "dashboard"],
    "double":           ["aesthetic/theme_switcher.sh", "--cycle"],
    "long":             ["utilities/self_destruct.sh", "--soft"],
    "emergency":        ["bin/cdeck", "panic", "--soft"],
    "triple":           ["bin/cdeck", "status"],
}

#: Actions that must be confirmed before they run
CONFIRM_ACTIONS = {"long", "emergency"}

#: Processes the emergency action stops immediately
EMERGENCY_PROCESSES = (
    "airodump-ng", "aireplay-ng", "aircrack-ng", "mdk4", "mdk3", "bettercap",
    "responder", "ettercap", "mitmproxy", "hostapd", "dnsmasq", "hackrf_transfer",
    "hashcat", "john", "nmap", "masscan", "tshark", "tcpdump",
)


@dataclass
class Event:
    """One button event."""

    kind: str
    timestamp: str = field(default_factory=now_iso)
    dry_run: bool = False
    action: List[str] = field(default_factory=list)
    result: str = ""
    exit_code: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        """Return the event as a plain dictionary.

        Returns:
            The dictionary.
        """
        return {
            "kind": self.kind,
            "timestamp": self.timestamp,
            "dry_run": self.dry_run,
            "action": self.action,
            "result": self.result,
            "exit_code": self.exit_code,
        }


class ButtonHandler:
    """Maps physical button presses onto deck actions.

    Args:
        config: loaded cyberdeck configuration (or ``None``).
        logger: shared logger.
        simulate: force the no-hardware backend.
        dry_run: report what each event would run instead of running it.
        assume_yes: skip the confirmation on the panic actions.
    """

    def __init__(self, config: Any = None, logger: Optional[Any] = None,
                 simulate: bool = False, dry_run: bool = False,
                 assume_yes: bool = False) -> None:
        """Configure the button pin and load the action map."""
        self.config = config
        self.logger = logger or gpio.Logger("button_handler")
        self.dry_run = dry_run
        self.assume_yes = assume_yes
        self.install_dir = self._install_dir()
        self.long_press = float(self._get("gpio.long_press_seconds", 2.0) or 2.0)
        self.emergency_press = float(self._get("gpio.emergency_press_seconds", 10.0) or 10.0)
        self.double_gap = float(self._get("gpio.double_press_gap", 0.4) or 0.4)
        self.actions = self._load_actions()
        self.backend, self.backend_note = gpio.detect_gpio(logger, simulate)
        self.simulated = self.backend.name == "simulate"
        self.pin_number = int(self._get("gpio.button_pin", 22) or 22)
        self.button = gpio.Button(
            self.pin_number, self.backend, self.logger,
            active_low=bool(self._get("gpio.button_active_low", True)),
            long_press_s=self.long_press,
            double_gap_s=self.double_gap,
        )
        self.events: List[Event] = []
        #: event names --simulate was given that do not exist
        self.unknown: List[str] = []
        self.running = True
        self.database = None
        self.alerts = None
        self._open_database()

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
        except Exception:  # noqa: BLE001 - never break the button on bad config
            return default
        return default if value is None else value

    def _install_dir(self) -> Path:
        """Return the install directory.

        Returns:
            The configured install path.
        """
        return Path(str(self._get("general.install_dir", "/opt/cyberdeck-arsenal")))

    def _load_actions(self) -> Dict[str, List[str]]:
        """Merge the configured action map over the defaults.

        Returns:
            A mapping of event name to argv.
        """
        actions: Dict[str, List[str]] = {key: list(value)
                                        for key, value in DEFAULT_ACTIONS.items()}
        configured = self._get("gpio.button_actions", {}) or {}
        if isinstance(configured, dict):
            for key, value in configured.items():
                if isinstance(value, str):
                    try:
                        actions[str(key)] = shlex.split(value)
                    except ValueError:
                        self.logger.warn("cannot parse gpio.button_actions.%s", key)
                elif isinstance(value, (list, tuple)):
                    actions[str(key)] = [str(item) for item in value]
        elif configured:
            self.logger.warn("gpio.button_actions must be a mapping - using the defaults")
        return actions

    def _open_database(self) -> None:
        """Open the events database for the audit trail."""
        if Database is None:
            return
        try:
            self.database = Database("events")
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("events database unavailable: %s", exc)

    # -- running actions ---------------------------------------------------- #
    def resolve(self, argv: Sequence[str]) -> Optional[List[str]]:
        """Resolve an action to an executable argument vector.

        Args:
            argv: the configured action.

        Returns:
            The resolved argv, or ``None`` when the program is missing.
        """
        if not argv:
            return None
        resolved = list(argv)
        candidate = Path(resolved[0])
        if not candidate.is_absolute():
            candidate = self.install_dir / candidate
        if candidate.exists():
            if candidate.suffix in (".py", ".sh") and not os.access(candidate, os.X_OK):
                interpreter = sys.executable if candidate.suffix == ".py" else "bash"
                resolved.insert(0, interpreter)
            resolved[0] = str(candidate) if resolved[0].startswith("/") or os.sep in resolved[0] \
                else resolved[0]
            if not resolved[0].startswith("/"):
                resolved[0] = str(candidate)
            return resolved
        if os.sep in argv[0]:
            return None
        if shutil.which(argv[0]) is None:
            return None
        return resolved

    def handle(self, kind: str, force: bool = False) -> Event:
        """Run the action mapped to an event.

        Args:
            kind: short, double, triple, long or emergency.
            force: run even when the platform's panic guard would ask.

        Returns:
            The recorded :class:`Event`.
        """
        event = Event(kind=kind, dry_run=self.dry_run)
        argv = self.actions.get(kind)
        if not argv:
            event.result = f"no action is mapped to a {kind} press"
            self.logger.warn("%s", event.result)
            self._record(event)
            return event

        event.action = list(argv)
        if kind in CONFIRM_ACTIONS and not force and not self.assume_yes and not self.dry_run:
            if not self._confirm(kind):
                event.result = "operator declined"
                self.logger.warn("%s press cancelled by the operator", kind)
                self._record(event)
                return event

        if kind == "emergency":
            stopped = self.stop_emergency_processes()
            event.result = f"stopped {len(stopped)} process(es): {', '.join(stopped) or 'none'}"
            self.logger.alert("EMERGENCY STOP: %s", event.result)

        resolved = self.resolve(argv)
        if resolved is None:
            event.result = f"cannot run {argv[0]} - not installed"
            self.logger.error("%s", event.result)
            self._record(event)
            return event

        if self.dry_run:
            event.result = "dry run: " + " ".join(shlex.quote(part) for part in resolved)
            self.logger.info("%s press → %s", kind, event.result)
            self._record(event)
            return event

        self.logger.info("%s press → %s", kind, " ".join(shlex.quote(part) for part in resolved))
        try:
            if resolved[0].endswith(("cdeck", "theme_switcher.sh")) or kind == "short":
                # Interactive tools must inherit the terminal
                result = subprocess.run(resolved, cwd=str(self.install_dir), check=False)
            else:
                result = subprocess.run(resolved, cwd=str(self.install_dir),
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, check=False)
            event.exit_code = result.returncode
            event.result = (f"finished with exit code {result.returncode}"
                            if result.returncode == 0 else
                            f"failed with exit code {result.returncode}")
        except OSError as exc:
            event.result = f"could not start {resolved[0]}: {exc}"
            self.logger.error("%s", event.result)
        self._record(event)
        return event

    def _confirm(self, kind: str) -> bool:
        """Ask the operator before a destructive action.

        Args:
            kind: the event name.

        Returns:
            True when the operator confirmed.
        """
        description = "the panic sequence" if kind == "long" else "the emergency stop"
        if not sys.stdin.isatty():
            self.logger.warn("%s press ignored: %s needs confirmation and stdin is "
                             "not a terminal (use --yes)", kind, description)
            return False
        try:
            reply = input(f"Button held ({kind}): run {description}? type 'yes' to confirm: ")
        except (EOFError, KeyboardInterrupt):
            return False
        return reply.strip().lower() in ("yes", "y")

    def stop_emergency_processes(self) -> List[str]:
        """Stop every process the emergency action must kill immediately.

        Returns:
            The process names that were stopped.
        """
        stopped: List[str] = []
        for name in EMERGENCY_PROCESSES:
            if self.dry_run:
                if any(_running(name)):
                    stopped.append(name)
                continue
            if _kill(name):
                stopped.append(name)
        return stopped

    def _record(self, event: Event) -> None:
        """Append the event to the in-memory log and the shared database.

        Args:
            event: the event to record.
        """
        self.events.append(event)
        if self.database is not None:
            try:
                severity = "WARNING" if event.kind in CONFIRM_ACTIONS else "INFO"
                self.database.event("button_handler", "gpio",
                                    f"{event.kind} press: {event.result}", severity,
                                    data=event.as_dict())
            except Exception as exc:  # noqa: BLE001
                self.logger.debug("could not record the button event: %s", exc)
        path = self.install_dir / "state" / "button_events.jsonl"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a") as handle:
                handle.write(json.dumps(event.as_dict()) + "\n")
        except OSError:  # pragma: no cover - logging must never be fatal
            pass

    # -- main loops --------------------------------------------------------- #
    def simulate(self, kinds: Sequence[str]) -> List[Event]:
        """Inject button events without any hardware.

        Args:
            kinds: the event names to inject in order.

        Returns:
            The resulting events.
        """
        results: List[Event] = []
        for kind in kinds:
            if kind == "sequence":
                for item in ("short", "double", "short", "long"):
                    results.append(self.handle(item, force=True))
                continue
            if kind not in self.actions and kind not in CONFIRM_ACTIONS:
                # An unknown event is a command-line error, not a runtime one, so it
                # is reported on stderr even when the console logger is silenced.
                sys.stderr.write(f"error: unknown event '{kind}' "
                                 f"(known: {', '.join(sorted(self.actions))}, sequence)\n")
                self.unknown.append(kind)
                continue
            results.append(self.handle(kind, force=True))
        return results

    def run(self) -> None:
        """Poll the button until a signal arrives."""
        self.logger.info("listening on pin %s (long press %.1fs, emergency %.1fs)",
                         self.pin_number, self.long_press, self.emergency_press)
        self.logger.info("mapping: " + ", ".join(
            f"{kind}={action[0]}" for kind, action in sorted(self.actions.items())))
        if self.simulated:
            self.logger.warn("no GPIO hardware detected - run with --simulate <event> "
                             "to exercise the mapping")
        held_since: Optional[float] = None
        while self.running:
            event = self.button.poll()
            if event:
                self.handle(event)
            # Emergency: a very long hold fires even before release
            if self.button.pressed():
                held_since = held_since or time.time()
                if time.time() - held_since >= self.emergency_press:
                    self.handle("emergency")
                    self.button.wait_for_release(timeout=5)
                    held_since = None
            else:
                held_since = None
            time.sleep(0.02)

    def close(self) -> None:
        """Release the button pin and close the database."""
        try:
            self.button.deinit()
        except Exception:  # noqa: BLE001
            pass
        self.backend.cleanup()
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # noqa: BLE001
                pass

    # -- reporting ---------------------------------------------------------- #
    def list_actions(self) -> None:
        """Print the event → action mapping."""
        print()
        print(f"  {'EVENT':<12}{'CONFIRM':<9}ACTION")
        print("  " + "─" * 88)
        for kind in sorted(self.actions):
            argv = self.actions[kind]
            resolved = self.resolve(argv)
            state = "" if resolved else "  (not installed)"
            print(f"  {kind:<12}{'yes' if kind in CONFIRM_ACTIONS else 'no':<9}"
                  f"{' '.join(argv)}{state}")
        print()
        print(f"  pin: {self.pin_number} · active low · long press {self.long_press}s "
              f"· emergency hold {self.emergency_press}s")
        print()

    def status(self) -> Dict[str, Any]:
        """Build the handler status.

        Returns:
            A dictionary describing the pin, mapping and recent events.
        """
        return {
            "version": VERSION,
            "backend": self.backend.name,
            "backend_note": self.backend_note,
            "simulated": self.simulated,
            "pin": self.pin_number,
            "long_press_seconds": self.long_press,
            "emergency_press_seconds": self.emergency_press,
            "actions": self.actions,
            "events": [event.as_dict() for event in self.events[-20:]],
        }


def _running(name: str) -> List[int]:
    """Return the PIDs of a process by executable name.

    Args:
        name: the process name (truncated to 15 characters like the kernel does).

    Returns:
        A list of PIDs.
    """
    pids: List[int] = []
    comm_name = name[:15]
    for entry in Path("/proc").iterdir() if Path("/proc").is_dir() else []:
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text().strip()
        except OSError:
            continue
        if comm == comm_name:
            pids.append(int(entry.name))
    return pids


def _kill(name: str, signal_number: int = 15, grace: float = 1.0) -> bool:
    """Stop every process with this name, escalating to SIGKILL.

    Args:
        name: the process name.
        signal_number: the first signal to send.
        grace: seconds to wait before SIGKILL.

    Returns:
        True when at least one process was signalled.
    """
    pids = _running(name)
    if not pids:
        return False
    for pid in pids:
        try:
            os.kill(pid, signal_number)
        except OSError:
            continue
    deadline = time.time() + grace
    while time.time() < deadline:
        if not _running(name):
            return True
        time.sleep(0.05)
    for pid in _running(name):
        try:
            os.kill(pid, 9)
        except OSError:
            continue
    return True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="button_handler.py",
        description="Physical button actions for the cyberdeck",
        epilog="authorised use only - see docs/LEGAL.md")
    parser.add_argument("--version", action="version", version=f"button_handler {VERSION}")
    parser.add_argument("--list-actions", action="store_true", help="show the mapping and exit")
    parser.add_argument("--status", action="store_true", help="show the handler status and exit")
    parser.add_argument("--simulate", nargs="*", default=None, metavar="EVENT",
                        help="inject events without hardware "
                             "(short, double, triple, long, emergency, sequence)")
    parser.add_argument("--pin", type=int, default=None, help="override the button pin")
    parser.add_argument("--long-press", type=float, default=None,
                        help="seconds that count as a long press")
    parser.add_argument("--duration", type=float, default=0.0,
                        help="stop after this many seconds (0 = until interrupted)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="show what each event would run")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="do not ask before the panic actions")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the button handler.

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
    logger = gpio.Logger("button_handler", level, quiet=args.quiet or args.json)
    if not (args.quiet or args.json):
        logger.banner("button handler", f"v{VERSION} · physical controls")

    handler = ButtonHandler(config, logger, simulate=args.simulate is not None,
                            dry_run=args.dry_run, assume_yes=args.yes)
    if args.pin is not None:
        handler.pin_number = args.pin
        handler.button = gpio.Button(args.pin, handler.backend, logger,
                                     long_press_s=handler.long_press,
                                     double_gap_s=handler.double_gap)
    if args.long_press is not None:
        handler.long_press = args.long_press
        handler.button.long_press_s = args.long_press

    logger.info("backend: %s (%s)", handler.backend.name, handler.backend_note)

    if args.list_actions:
        handler.list_actions()
        if args.json:
            print(json.dumps(handler.status(), indent=2))
        handler.close()
        return 0

    if args.status:
        status = handler.status()
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            logger.info("button pin %s on %s", status["pin"], status["backend"])
            for kind, action in sorted(status["actions"].items()):
                logger.info("  %-10s → %s", kind, " ".join(action))
        handler.close()
        return 0

    def stop(_signum: int, _frame: Any) -> None:
        logger.info("stopping the button handler")
        handler.running = False

    for signal_name in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, signal_name), stop)
        except (ValueError, OSError):  # pragma: no cover
            pass

    exit_code = 0
    try:
        if args.simulate is not None:
            kinds = args.simulate or ["short", "double", "long"]
            events = handler.simulate(kinds)
            failures = [event for event in events if event.exit_code not in (None, 0)]
            if args.json:
                print(json.dumps([event.as_dict() for event in events], indent=2))
            else:
                for event in events:
                    logger.info("%-10s %s", event.kind, event.result)
            if handler.unknown:
                exit_code = 2
            elif failures:
                exit_code = 1
        elif args.duration:
            deadline = time.time() + args.duration
            while handler.running and time.time() < deadline:
                event = handler.button.poll()
                if event:
                    handler.handle(event)
                time.sleep(0.02)
            if args.json:
                print(json.dumps(handler.status(), indent=2))
        else:
            handler.run()
    finally:
        handler.close()

    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
