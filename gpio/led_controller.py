#!/usr/bin/env python3
"""
gpio/led_controller.py - status, alert and activity LEDs for the deck.
======================================================================

Description
-----------
Drives the deck's LEDs. Two pins are configured in ``cyberdeck.conf``
(``gpio.status_led_pin``, default BCM 17 and ``gpio.alert_led_pin``, default BCM
27), each running an independent pattern from
:mod:`cybergpio`-style blink definitions:

============ =========================================================
``off``      always dark
``on``       steady light
``heartbeat`` the deck is alive (two quick pulses, then a pause)
``slow``     idle but awake
``fast``     work in progress: capture, scan or replay running
``recording`` a capture is being written
``alert``    an alert was raised
``strobe``   something is wrong - continuous strobing
``sos``      Morse SOS, used by the panic path
``double``   a notification arrived
``breathe``  soft fade for a deck sitting on a desk
============ =========================================================

Modes
-----
* ``--pattern NAME``  run one pattern on one or both LEDs
* ``--state STATE``   map a deck state (idle, scanning, capturing, alert,
  panic, vpn, offline) to the right patterns for both LEDs
* ``--watch``         follow the living system: running processes, the newest
  alert in the database and the network state, updating the LEDs as it changes
* ``--alerts``        register as the alert LED hook so ``cyberlib.Alerts.send``
  strobing the alert LED whenever anything on the deck raises an alert
* ``--test``          walk through every pattern so you can pick a favourite

Without GPIO hardware the tool detects that honestly and keeps running against
the simulated backend (``--simulate`` forces it), so it is usable on a laptop or
in CI. The simulated backend can print every transition (``--verbose``).

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library, lib/cybergpio.py
              optional: lgpio / RPi.GPIO / gpiod for real pins
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Usage
-----
    sudo ./led_controller.py --state idle
    ./led_controller.py --pattern heartbeat --led status
    ./led_controller.py --watch --simulate --verbose
    ./led_controller.py --alerts
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
    from cyberlib import Alerts, Config, Database, Logger, colour, now_iso  # type: ignore
except ImportError:  # pragma: no cover - cyberlib is optional here
    from cybergpio import Logger, colour  # type: ignore

    Config = None  # type: ignore
    Alerts = None  # type: ignore
    Database = None  # type: ignore

    def now_iso() -> str:
        """Fallback timestamp helper.

        Returns:
            An ISO-8601 timestamp.
        """
        from datetime import datetime
        return datetime.now().astimezone().isoformat(timespec="seconds")

VERSION = "1.0.0"

#: Deck states and the patterns they imply for (status LED, alert LED)
STATE_MAP: Dict[str, Tuple[str, str]] = {
    "idle":       ("heartbeat", "off"),
    "ready":      ("slow", "off"),
    "scanning":   ("fast", "off"),
    "capturing":  ("recording", "off"),
    "replaying":  ("fast", "off"),
    "vpn":        ("breathe", "off"),
    "offline":    ("slow", "double"),
    "alert":      ("fast", "alert"),
    "warning":    ("slow", "double"),
    "critical":   ("fast", "strobe"),
    "panic":      ("off", "sos"),
    "off":        ("off", "off"),
}

#: Process names that mean "the deck is working", mapped to a state
PROCESS_STATES: Tuple[Tuple[str, str], ...] = (
    ("airodump-ng", "capturing"),
    ("tshark", "capturing"),
    ("tcpdump", "capturing"),
    ("dump1090", "capturing"),
    ("rtl_fm", "capturing"),
    ("rtl_sdr", "capturing"),
    ("hackrf_transfer", "replaying"),
    ("nmap", "scanning"),
    ("masscan", "scanning"),
    ("bettercap", "scanning"),
    ("responder", "scanning"),
    ("hashcat", "scanning"),
    ("john", "scanning"),
)

SEVERITY_STATES = {
    "CRITICAL": "critical",
    "ALERT": "critical",
    "ERROR": "alert",
    "HIGH": "alert",
    "WARNING": "warning",
    "MEDIUM": "warning",
    "INFO": "ready",
    "LOW": "ready",
}


@dataclass
class LedState:
    """The pattern a single LED is currently running."""

    name: str
    since: str
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """Return the state as a plain dictionary.

        Returns:
            The dictionary.
        """
        return {"pattern": self.name, "since": self.since, "reason": self.reason}


class LedController:
    """Drives the two deck LEDs through any available GPIO backend.

    Args:
        config: loaded cyberdeck configuration (or ``None`` for defaults).
        logger: shared logger.
        simulate: force the no-hardware backend.
        verbose: print every pin transition.
    """

    def __init__(self, config: Any = None, logger: Optional[Any] = None,
                 simulate: bool = False, verbose: bool = False) -> None:
        """Probe the hardware and configure both pins."""
        self.config = config
        self.logger = logger or gpio.Logger("led_controller")
        self.verbose = verbose
        self.interval = float(self._get("gpio.blink_interval", 0.5) or 0.5)
        self.enabled = bool(self._get("gpio.enabled", False))
        self.backend, self.backend_note = gpio.detect_gpio(self.logger, simulate,
                                                           verbose)
        self.simulated = self.backend.name == "simulate"
        self.patterns = gpio.builtin_patterns(self.interval)
        self.status_pattern = LedState("off", now_iso())
        self.alert_pattern = LedState("off", now_iso())
        self.status_fired = 0
        self.alert_fired = 0
        self.pin_status: Optional[gpio.Pin] = None
        self.pin_alert: Optional[gpio.Pin] = None
        self.running = True
        self.alerts = None
        self.database = None
        self._open_pins()

    # -- configuration ----------------------------------------------------- #
    def _get(self, dotted: str, default: Any = None) -> Any:
        """Read a configuration value with a safe fallback.

        Args:
            dotted: the ``section.key`` path.
            default: value used when the config is absent.

        Returns:
            The configured value.
        """
        if self.config is None:
            return default
        try:
            value = self.config.get(dotted, default)
        except Exception:  # noqa: BLE001 - configuration must never break the LEDs
            return default
        return default if value is None else value

    def _open_pins(self) -> None:
        """Configure the two LED pins."""
        status_pin = int(self._get("gpio.status_led_pin", 17) or 17)
        alert_pin = int(self._get("gpio.alert_led_pin", 27) or 27)
        try:
            self.pin_status = gpio.Pin(status_pin, self.backend, self.logger, mode="out")
            self.pin_alert = gpio.Pin(alert_pin, self.backend, self.logger, mode="out")
        except Exception as exc:  # noqa: BLE001 - fall back rather than crash
            self.logger.error("could not configure the LED pins: %s", exc)
            self.logger.warn("continuing with the simulated backend")
            self.backend = gpio.SimulatedBackend(self.logger, self.verbose)
            self.simulated = True
            self.pin_status = gpio.Pin(status_pin, self.backend, self.logger, mode="out")
            self.pin_alert = gpio.Pin(alert_pin, self.backend, self.logger, mode="out")
        self.logger.debug("LED pins: status %s, alert %s (%s)",
                          status_pin, alert_pin, self.backend_note)

    # -- pattern driving ---------------------------------------------------- #
    def set_pattern(self, led: str, name: str, reason: str = "") -> bool:
        """Change the pattern running on one LED.

        Args:
            led: ``status``, ``alert`` or ``both``.
            name: the pattern name.
            reason: why the change happened (logged).

        Returns:
            True when the pattern exists and was applied.
        """
        if name not in self.patterns:
            self.logger.error("unknown pattern '%s' (see --list-patterns)", name)
            return False
        stamp = now_iso()
        targets: List[str] = []
        if led in ("status", "both"):
            targets.append("status")
        if led in ("alert", "both"):
            targets.append("alert")
        for target in targets:
            if target == "status":
                self.status_pattern = LedState(name, stamp, reason)
                self.status_fired = 0
            else:
                self.alert_pattern = LedState(name, stamp, reason)
                self.alert_fired = 0
        if reason:
            self.logger.info("%s LED → %s (%s)", led, name, reason)
        else:
            self.logger.info("%s LED → %s", led, name)
        return True

    def state(self, state_name: str, reason: str = "") -> bool:
        """Apply the patterns belonging to a deck state.

        Args:
            state_name: a key of :data:`STATE_MAP`.
            reason: why the state changed.

        Returns:
            True when the state is known.
        """
        state_name = state_name.lower()
        if state_name not in STATE_MAP:
            self.logger.error("unknown state '%s' (known: %s)",
                              state_name, ", ".join(sorted(STATE_MAP)))
            return False
        status_pattern, alert_pattern = STATE_MAP[state_name]
        self.set_pattern("status", status_pattern, reason or f"state {state_name}")
        self.set_pattern("alert", alert_pattern, reason or f"state {state_name}")
        return True

    def step(self) -> None:
        """Advance both patterns by one frame (non-blocking)."""
        for led, state, pin, counter_name in (
            ("status", self.status_pattern, self.pin_status, "status_fired"),
            ("alert", self.alert_pattern, self.pin_alert, "alert_fired"),
        ):
            if pin is None:
                continue
            pattern = self.patterns[state.name]
            if not pattern.steps:
                pin.write(0)
                continue
            if len(pattern.steps) == 1:
                # Steady patterns hold their level
                pin.write(pattern.steps[0][0])
                continue
            index = getattr(self, counter_name) % len(pattern.steps)
            level, seconds = pattern.steps[index]
            pin.write(level)
            setattr(self, counter_name, index + 1)
            # Sleep no longer than the shortest step in either pattern
            del seconds
            del led

    def step_delay(self) -> float:
        """Return how long to wait before the next frame.

        Returns:
            The delay in seconds, based on the fastest running pattern.
        """
        delays: List[float] = []
        for state in (self.status_pattern, self.alert_pattern):
            pattern = self.patterns[state.name]
            if len(pattern.steps) > 1:
                delays.append(min(seconds for _, seconds in pattern.steps))
        if not delays:
            return 0.5
        return max(0.02, min(delays))

    def run_pattern(self, seconds: Optional[float] = None) -> None:
        """Play the current patterns until interrupted.

        Args:
            seconds: stop after this long (``None`` = until a signal).
        """
        deadline = None if seconds is None else time.time() + seconds
        delay = self.step_delay()
        while self.running:
            self.step()
            if deadline is not None and time.time() >= deadline:
                break
            time.sleep(max(0.01, min(delay, 1.0)))
        # Note: the pins are turned off by close(), not here, so callers can
        # report the pattern that was running when they asked for the summary.

    def off(self) -> None:
        """Turn both LEDs off."""
        for pin in (self.pin_status, self.pin_alert):
            if pin is not None:
                try:
                    pin.write(0)
                except Exception:  # noqa: BLE001
                    pass
        self.status_pattern = LedState("off", now_iso(), "shutdown")
        self.alert_pattern = LedState("off", now_iso(), "shutdown")

    def close(self) -> None:
        """Turn the LEDs off and release the pins."""
        self.off()
        for pin in (self.pin_status, self.pin_alert):
            if pin is not None:
                try:
                    pin.deinit()
                except Exception:  # noqa: BLE001
                    pass
        self.backend.cleanup()
        if self.database is not None:
            try:
                self.database.close()
            except Exception:  # noqa: BLE001
                pass

    # -- integrations ------------------------------------------------------- #
    def register_alert_hook(self) -> bool:
        """Register this controller as the shared library's LED hook.

        Returns:
            True when the hook was registered.
        """
        if Alerts is None or self.config is None:
            self.logger.warn("cyberlib alerts are unavailable - LED hook not registered")
            return False
        try:
            self.alerts = Alerts("led_controller", self.config, self.logger)
            self.alerts.register_led_hook(self.on_alert)
        except Exception as exc:  # noqa: BLE001
            self.logger.error("could not register the alert hook: %s", exc)
            return False
        self.logger.ok("alert LED hook registered - alerts now strobe the alert LED")
        return True

    def on_alert(self, severity: str) -> None:
        """Handle an alert severity from the shared library.

        Args:
            severity: INFO, WARNING, ERROR, CRITICAL, ...
        """
        state_name = SEVERITY_STATES.get(str(severity).upper(), "warning")
        self.state(state_name, f"alert severity {severity}")
        # Flashes the new pattern for a moment, then settles if the deck is calm
        delay = self.step_delay()
        for _ in range(6):
            self.step()
            time.sleep(max(0.02, delay))

    def detect_state(self) -> Tuple[str, str]:
        """Work out what the deck is doing right now.

        Returns:
            A ``(state, reason)`` pair.
        """
        for process, state_name in PROCESS_STATES:
            if process_running(process):
                return state_name, f"{process} is running"

        severity = newest_alert_severity(self._install_dir())
        if severity:
            state_name = SEVERITY_STATES.get(severity, "warning")
            if state_name in ("critical", "alert", "warning"):
                return state_name, f"newest alert is {severity}"

        if not default_route_up():
            return "offline", "no default route"
        if vpn_active():
            return "vpn", "VPN tunnel is up"
        return "idle", "nothing is running"

    def _install_dir(self) -> Path:
        """Return the configured install directory.

        Returns:
            The install directory path.
        """
        value = self._get("general.install_dir", "/opt/cyberdeck-arsenal")
        return Path(str(value))

    def watch(self, interval: float = 3.0) -> None:
        """Follow the deck's state and keep the LEDs in step.

        Args:
            interval: how often to re-evaluate the state.
        """
        self.logger.info("watching the deck state (Ctrl-C to stop)")
        current = ""
        last_change = 0.0
        delay = self.step_delay()
        while self.running:
            now = time.time()
            if now - last_change >= interval:
                state_name, reason = self.detect_state()
                if state_name != current:
                    current = state_name
                    self.state(state_name, reason)
                    delay = self.step_delay()
                last_change = now
            self.step()
            time.sleep(max(0.02, min(delay, 0.5)))

    # -- reporting ---------------------------------------------------------- #
    def list_patterns(self) -> None:
        """Print every pattern with its description and timings."""
        print()
        print(f"  {'PATTERN':<12}{'TOTAL':>8}  DESCRIPTION")
        print("  " + "─" * 88)
        for name, pattern in self.patterns.items():
            total = sum(seconds for _, seconds in pattern.steps)
            print(f"  {name:<12}{total:>7.2f}s  {pattern.description}")
        print()
        print("  states:")
        for state_name, (status_pattern, alert_pattern) in STATE_MAP.items():
            print(f"    {state_name:<10} status={status_pattern:<10} alert={alert_pattern}")
        print()

    def status(self) -> Dict[str, Any]:
        """Build the current controller status.

        Returns:
            A dictionary describing the pins and patterns.
        """
        return {
            "version": VERSION,
            "backend": self.backend.name,
            "backend_note": self.backend_note,
            "simulated": self.simulated,
            "enabled_in_config": self.enabled,
            "blink_interval": self.interval,
            "status_pin": self.pin_status.number if self.pin_status else None,
            "alert_pin": self.pin_alert.number if self.pin_alert else None,
            "status": self.status_pattern.as_dict(),
            "alert": self.alert_pattern.as_dict(),
            "states": {key: {"status": value[0], "alert": value[1]}
                       for key, value in STATE_MAP.items()},
        }


# --------------------------------------------------------------------------- #
# System probes (kept as module functions so they are easy to test)
# --------------------------------------------------------------------------- #
def process_running(name: str) -> bool:
    """Return True when a process with this name is running.

    Args:
        name: the executable name.

    Returns:
        True when at least one matching process exists.
    """
    if len(name) > 15:
        name = name[:15]
    proc = Path("/proc")
    if not proc.is_dir():
        return False
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text().strip()
        except OSError:
            continue
        if comm == name:
            return True
    return False


def newest_alert_severity(install_dir: Path, minutes: int = 30) -> str:
    """Return the severity of the newest recent alert, if any.

    Args:
        install_dir: the install root holding ``data/events.db``.
        minutes: how recent an alert must be to count.

    Returns:
        The severity string, or an empty string.
    """
    path = install_dir / "data" / "events.db"
    if not path.is_file():
        return ""
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            row = connection.execute(
                "SELECT severity FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
            if not row:
                return ""
            # Only treat it as current if it is recent
            recent = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= datetime('now', ?)",
                (f"-{int(minutes)} minutes",)).fetchone()
    except sqlite3.Error:
        return ""
    if not recent or int(recent[0]) == 0:
        return ""
    return str(row[0] or "").upper()


def default_route_up() -> bool:
    """Return True when the host has a default route.

    Returns:
        True when a default route exists.
    """
    try:
        result = subprocess.run(["ip", "route", "show", "default"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
        return b"default" in result.stdout
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        return False


def vpn_active() -> bool:
    """Return True when a VPN or Tor tunnel is up.

    Returns:
        True when wireguard, openvpn or tor is active.
    """
    if process_running("openvpn") or process_running("tor"):
        return True
    try:
        result = subprocess.run(["ip", "link", "show", "type", "wireguard"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
        return b"wg" in result.stdout
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        return False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="led_controller.py",
        description="Pattern-driven status and alert LEDs for the cyberdeck",
        epilog="authorised use only - see docs/LEGAL.md")
    parser.add_argument("--version", action="version", version=f"led_controller {VERSION}")
    parser.add_argument("--pattern", default="", help="run a named pattern")
    parser.add_argument("--state", default="", help="apply a deck state's patterns")
    parser.add_argument("--led", default="both", choices=["status", "alert", "both"],
                        help="which LED to drive (default: both)")
    parser.add_argument("--list-patterns", action="store_true", help="show every pattern")
    parser.add_argument("--test", action="store_true", help="walk through every pattern")
    parser.add_argument("--watch", action="store_true",
                        help="follow the deck's state and update the LEDs")
    parser.add_argument("--alerts", action="store_true",
                        help="register the alert hook and follow alerts")
    parser.add_argument("--duration", type=float, default=0.0,
                        help="stop after this many seconds (0 = until interrupted)")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="state polling interval for --watch (default: 3s)")
    parser.add_argument("--status-pin", type=int, default=None, help="override the status pin")
    parser.add_argument("--alert-pin", type=int, default=None, help="override the alert pin")
    parser.add_argument("--simulate", action="store_true", help="force the no-hardware backend")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="print every pin transition (simulated backend)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the LED controller.

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
        except Exception:  # noqa: BLE001 - run with defaults if the config is broken
            config = None
    logger = gpio.Logger("led_controller", level, quiet=args.quiet or args.json)
    if not (args.quiet or args.json):
        logger.banner("LED controller", f"v{VERSION} · status and alert LEDs")

    controller = LedController(config, logger, simulate=args.simulate, verbose=args.verbose)
    if args.status_pin is not None:
        controller.pin_status = gpio.Pin(args.status_pin, controller.backend, logger, "out")
    if args.alert_pin is not None:
        controller.pin_alert = gpio.Pin(args.alert_pin, controller.backend, logger, "out")
    logger.info("backend: %s (%s)", controller.backend.name, controller.backend_note)
    if controller.simulated and not args.json:
        logger.warn("no GPIO hardware detected - the LEDs are simulated")

    if args.list_patterns:
        controller.list_patterns()
        if args.json:
            print(json.dumps({"patterns": {name: pattern.as_dict()
                                           for name, pattern in controller.patterns.items()},
                              "states": STATE_MAP}, indent=2))
        controller.close()
        return 0

    if args.test:
        logger.info("walking through every pattern - watch the LEDs")
        for name in controller.patterns:
            if not controller.running:
                break
            logger.info("pattern: %s", name)
            controller.set_pattern("both", name)
            controller.run_pattern(4.0 if name != "sos" else 8.0)
        controller.close()
        logger.ok("pattern walk finished")
        return 0

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal_running(controller)

    for signal_name in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, signal_name), stop)
        except (ValueError, OSError):  # pragma: no cover
            pass

    snapshot: Dict[str, Any] = {}
    try:
        if args.pattern:
            if not controller.set_pattern(args.led, args.pattern):
                return 2
            controller.run_pattern(args.duration or None)
        elif args.state:
            if not controller.state(args.state):
                return 2
            controller.run_pattern(args.duration or None)
        elif args.alerts:
            if not controller.register_alert_hook():
                return 3
            controller.state("ready", "waiting for alerts")
            deadline = None if not args.duration else time.time() + args.duration
            delay = controller.step_delay()
            while controller.running:
                controller.step()
                if deadline is not None and time.time() >= deadline:
                    break
                time.sleep(max(0.02, min(delay, 0.5)))
        elif args.watch:
            if args.duration:
                deadline = time.time() + args.duration
                previous = ""
                while controller.running and time.time() < deadline:
                    state_name, reason = controller.detect_state()
                    if state_name != previous:
                        previous = state_name
                        controller.state(state_name, reason)
                        logger.info("deck state: %s (%s)", state_name, reason)
                    controller.step()
                    time.sleep(max(0.05, args.interval))
            else:
                controller.watch(args.interval)
        else:
            # No action chosen: report what the deck is doing and set the LEDs
            state_name, reason = controller.detect_state()
            controller.state(state_name, reason)
            if args.json:
                print(json.dumps({**controller.status(), "detected_state": state_name,
                                  "reason": reason}, indent=2))
                controller.close()
                return 0
            logger.ok("deck state: %s (%s)", state_name, reason)
            controller.list_patterns()
            controller.close()
            return 0
    finally:
        snapshot = controller.status()
        controller.close()

    if args.json:
        print(json.dumps(snapshot, indent=2))
    else:
        logger.ok("finished")
    return 0


def nonlocal_running(controller: LedController) -> None:
    """Signal handler helper: tell the controller to stop.

    Args:
        controller: the controller to stop.
    """
    controller.logger.info("stopping the LED controller")
    controller.running = False


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
