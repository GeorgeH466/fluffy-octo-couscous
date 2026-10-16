#!/usr/bin/env python3
"""
lib/cybergpio.py - GPIO, I2C and small-display support for the deck.
====================================================================

Description
-----------
One shared, hardware-agnostic layer for the three tools under ``gpio/`` (the LED
controller, the button handler and the OLED display) so the pin handling, the
backend probing and the I2C plumbing exist exactly once.

Backends, tried in this order:

1. **lgpio** or **RPi.GPIO** - the usual Raspberry Pi libraries
2. **gpiod** (libgpiod v1/v2 Python bindings) - generic Linux SBCs
3. **sysfs** - ``/sys/class/gpio``, available on most kernels
4. **simulate** - no hardware: transitions are logged and optionally printed, so
   the tool still works on a laptop, in CI, or on a deck with no GPIO header

Included here:

* :class:`Pin` - output/input pin with debounced reads and timed pulses
* :class:`LedPattern` - named blink patterns (heartbeat, alert, panic, ...)
* :class:`Button` - short / long / double press detection with callbacks
* :class:`SSD1306` - a dependency-free SSD1306/SH1106 OLED driver that talks to
  ``/dev/i2c-*`` directly through ``fcntl`` ioctl, plus a full printable ASCII
  5x7 font (the font lives here as readable ASCII art, see :data:`FONT_ART`)
* :func:`detect_gpio` - probe every backend and report what is available

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library; optional: lgpio, RPi.GPIO, gpiod
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Command line
------------
    python3 lib/cybergpio.py --detect          # what hardware is available
    python3 lib/cybergpio.py --selftest        # exercise pins and the OLED
    python3 lib/cybergpio.py --i2c-scan        # list devices on the I2C buses
    python3 lib/cybergpio.py --font A          # print a font glyph as ASCII art
    python3 lib/cybergpio.py --dump-font       # render the whole font as art
"""

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
import signal
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
VERSION = "1.0.0"

SYSFS_GPIO = Path("/sys/class/gpio")
I2C_DEV_ROOT = Path("/dev")

#: ``fcntl.ioctl`` request that binds a file descriptor to an I2C slave address
I2C_SLAVE = 0x0703

#: Human-readable names for the GPIO modes
MODES = ("out", "in", "rising", "falling", "both")

#: LED states a deck usually wants to signal
LED_STATES = (
    "off", "on", "heartbeat", "slow", "fast", "strobe", "sos", "double",
    "breathe", "alert", "recording",
)

#: SSD1306 commands
SSD1306_SET_CONTRAST = 0x81
SSD1306_DISPLAY_ALL_ON_RESUME = 0xA4
SSD1306_NORMAL_DISPLAY = 0xA6
SSD1306_INVERT_DISPLAY = 0xA7
SSD1306_DISPLAY_OFF = 0xAE
SSD1306_DISPLAY_ON = 0xAF
SSD1306_SET_DISPLAY_OFFSET = 0xD3
SSD1306_SET_COM_PINS = 0xDA
SSD1306_SET_VCOM_DETECT = 0xDB
SSD1306_SET_DISPLAY_CLOCK_DIV = 0xD5
SSD1306_SET_PRECHARGE = 0xD9
SSD1306_SET_MULTIPLEX = 0xA8
SSD1306_SET_LOW_COLUMN = 0x00
SSD1306_SET_HIGH_COLUMN = 0x10
SSD1306_SET_START_LINE = 0x40
SSD1306_MEMORY_MODE = 0x20
SSD1306_COLUMN_ADDR = 0x21
SSD1306_PAGE_ADDR = 0x22
SSD1306_COM_SCAN_INC = 0xC0
SSD1306_COM_SCAN_DEC = 0xC8
SSD1306_SEG_REMAP = 0xA0
SSD1306_CHARGE_PUMP = 0x8D

#: The printable ASCII range covered by the built-in font
FONT_FIRST = 32
FONT_LAST = 126

#: Ascending list of font glyph keys, used for validation messages
def _font_keys() -> List[str]:
    """Return every character the built-in font must define.

    Returns:
        The characters from space to tilde.
    """
    return [chr(code) for code in range(FONT_FIRST, FONT_LAST + 1)]


# --------------------------------------------------------------------------- #
# Logging (works with or without the shared library)
# --------------------------------------------------------------------------- #
try:  # pragma: no cover - exercised by the real installs
    from cyberlib import Logger, colour  # type: ignore
except Exception:  # noqa: BLE001 - cybergpio must be importable on its own
    def colour(text: str, code: str = "") -> str:  # type: ignore
        """Fallback colouriser that returns plain text."""
        del code
        return text

    class Logger:  # type: ignore
        """Minimal stand-in for :class:`cyberlib.Logger`."""

        def __init__(self, name: str = "cybergpio", level: str = "INFO",
                     quiet: bool = False) -> None:
            self.name = name
            self._logger = logging.getLogger(name)
            if not self._logger.handlers:
                logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                                    format="%(asctime)s %(levelname)-8s %(message)s")
            self.level_name = level.upper()
            self.quiet = quiet

        def _emit(self, level: int, message: str, *args: Any) -> None:
            if self.quiet and level < logging.WARNING:
                return
            self._logger.log(level, message, *args)

        def debug(self, message: str, *args: Any) -> None:
            self._emit(logging.DEBUG, message, *args)

        def info(self, message: str, *args: Any) -> None:
            self._emit(logging.INFO, message, *args)

        def ok(self, message: str, *args: Any) -> None:
            self._emit(logging.INFO, message, *args)

        def warn(self, message: str, *args: Any) -> None:
            self._emit(logging.WARNING, message, *args)

        def error(self, message: str, *args: Any) -> None:
            self._emit(logging.ERROR, message, *args)

        def critical(self, message: str, *args: Any) -> None:
            self._emit(logging.CRITICAL, message, *args)

        def banner(self, title: str, subtitle: str = "") -> None:
            self.info("%s %s", title, subtitle)


def parse_font(art: str) -> Dict[str, List[int]]:
    """Parse a 5x7 font written as ASCII art.

    The art format is one glyph per column group: seven lines of art, each line
    holding that row for a run of glyphs, separated by whitespace. It is the
    format :func:`font_to_art` writes, which makes it round-trippable and easy
    to hand-edit.

    Args:
        art: the block of art ('#' or '*' for a lit pixel, anything else dark).

    Returns:
        A mapping of single characters to seven row bytes (bit 4 is the leftmost
        column).

    Raises:
        ValueError: when the art is not a whole number of 7-line blocks or a row
            is not 5 columns wide.
    """
    lines = [line.strip() for line in art.strip("\n").splitlines() if line.strip()]
    if len(lines) % 7:
        raise ValueError(f"font art must have a multiple of 7 lines, got {len(lines)}")
    glyphs: Dict[str, List[int]] = {}
    code = FONT_FIRST
    for block_start in range(0, len(lines), 7):
        block = [line.split() for line in lines[block_start:block_start + 7]]
        widths = {len(row) for row in block}
        if len(widths) != 1:
            raise ValueError("font art lines in a block must hold the same "
                             f"number of glyphs (got {sorted(widths)})")
        count = widths.pop()
        for index in range(count):
            if code > FONT_LAST:
                break
            bitmap: List[int] = []
            for row in block:
                glyph_row = row[index]
                if len(glyph_row) != 5:
                    raise ValueError(
                        f"glyph {chr(code)!r} row is {len(glyph_row)} wide, expected 5")
                value = 0
                for column, character in enumerate(glyph_row):
                    if character in "#*X":
                        value |= 1 << (4 - column)
                bitmap.append(value)
            glyphs[chr(code)] = bitmap
            code += 1
    return glyphs


def font_to_art(font: Dict[str, List[int]], glyphs_per_line: int = 12) -> str:
    """Render a font as ASCII art (the inverse of :func:`parse_font`).

    Args:
        font: the font mapping.
        glyphs_per_line: how many glyphs to put on each line.

    Returns:
        The art block.
    """
    keys = sorted(font)
    glyphs_per_line = max(1, int(glyphs_per_line))
    lines: List[str] = []
    for start in range(0, len(keys), glyphs_per_line):
        chunk = keys[start:start + glyphs_per_line]
        for row in range(7):
            lines.append(" ".join(
                "".join("#" if font[key][row] & (1 << (4 - column)) else "."
                        for column in range(5)) for key in chunk))
    return "\n".join(lines) + "\n"


GENERATED_FONT: Dict[str, List[int]] = {
    " ": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "!": [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
    '"': [0x0A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00],
    "#": [0x0A, 0x1F, 0x0A, 0x0A, 0x1F, 0x0A, 0x00],
    "$": [0x04, 0x0F, 0x14, 0x0E, 0x05, 0x1E, 0x04],
    "%": [0x18, 0x19, 0x02, 0x04, 0x08, 0x13, 0x03],
    "&": [0x08, 0x14, 0x14, 0x08, 0x15, 0x12, 0x0D],
    "'": [0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00],
    "(": [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
    ")": [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
    "*": [0x00, 0x0A, 0x04, 0x1F, 0x04, 0x0A, 0x00],
    "+": [0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00],
    ",": [0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08],
    "-": [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
    ".": [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
    "/": [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
    "0": [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
    "1": [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "2": [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
    "3": [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E],
    "4": [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
    "5": [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
    "6": [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
    "7": [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
    "8": [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
    "9": [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
    ":": [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
    ";": [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x04, 0x08],
    "<": [0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02],
    "=": [0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00],
    ">": [0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08],
    "?": [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
    "@": [0x0E, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0E],
    "A": [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
    "B": [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
    "C": [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
    "D": [0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E],
    "E": [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
    "F": [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
    "G": [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
    "H": [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
    "I": [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "J": [0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C],
    "K": [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
    "L": [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
    "M": [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
    "N": [0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11],
    "O": [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
    "P": [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
    "Q": [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
    "R": [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
    "S": [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
    "T": [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
    "U": [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
    "V": [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
    "W": [0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11],
    "X": [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
    "Y": [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
    "Z": [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
    "[": [0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E],
    "\\": [0x10, 0x08, 0x08, 0x04, 0x02, 0x02, 0x01],
    "]": [0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E],
    "^": [0x04, 0x0A, 0x11, 0x00, 0x00, 0x00, 0x00],
    "_": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F],
    "`": [0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00],
    "a": [0x00, 0x00, 0x0E, 0x01, 0x0F, 0x11, 0x0F],
    "b": [0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x1E],
    "c": [0x00, 0x00, 0x0F, 0x10, 0x10, 0x10, 0x0F],
    "d": [0x01, 0x01, 0x0F, 0x11, 0x11, 0x11, 0x0F],
    "e": [0x00, 0x00, 0x0E, 0x11, 0x1F, 0x10, 0x0E],
    "f": [0x06, 0x09, 0x08, 0x1C, 0x08, 0x08, 0x08],
    "g": [0x00, 0x0F, 0x11, 0x11, 0x0F, 0x01, 0x0E],
    "h": [0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x11],
    "i": [0x04, 0x00, 0x0C, 0x04, 0x04, 0x04, 0x0E],
    "j": [0x02, 0x00, 0x06, 0x02, 0x02, 0x12, 0x0C],
    "k": [0x10, 0x10, 0x12, 0x14, 0x18, 0x14, 0x12],
    "l": [0x0C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "m": [0x00, 0x00, 0x1A, 0x15, 0x15, 0x15, 0x15],
    "n": [0x00, 0x00, 0x1E, 0x11, 0x11, 0x11, 0x11],
    "o": [0x00, 0x00, 0x0E, 0x11, 0x11, 0x11, 0x0E],
    "p": [0x00, 0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10],
    "q": [0x00, 0x0F, 0x11, 0x11, 0x0F, 0x01, 0x01],
    "r": [0x00, 0x00, 0x16, 0x19, 0x10, 0x10, 0x10],
    "s": [0x00, 0x00, 0x0F, 0x10, 0x0E, 0x01, 0x1E],
    "t": [0x08, 0x08, 0x1C, 0x08, 0x08, 0x09, 0x06],
    "u": [0x00, 0x00, 0x11, 0x11, 0x11, 0x13, 0x0D],
    "v": [0x00, 0x00, 0x11, 0x11, 0x11, 0x0A, 0x04],
    "w": [0x00, 0x00, 0x11, 0x11, 0x15, 0x15, 0x0A],
    "x": [0x00, 0x00, 0x11, 0x0A, 0x04, 0x0A, 0x11],
    "y": [0x00, 0x11, 0x11, 0x11, 0x0F, 0x01, 0x0E],
    "z": [0x00, 0x00, 0x1F, 0x02, 0x04, 0x08, 0x1F],
    "{": [0x02, 0x04, 0x04, 0x08, 0x04, 0x04, 0x02],
    "|": [0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
    "}": [0x08, 0x04, 0x04, 0x02, 0x04, 0x04, 0x08],
    "~": [0x00, 0x00, 0x08, 0x15, 0x02, 0x00, 0x00],
}


def complete_font() -> Dict[str, List[int]]:
    """Return the built-in 5x7 font for the whole printable ASCII range.

    The table above is the source of truth; :func:`parse_font` (ASCII art) and
    :data:`GENERATED_ART` (the same table rendered as art) exist so the font can
    be reviewed visually and replaced with a custom one.

    Returns:
        A mapping of character to seven row bytes.

    Raises:
        ValueError: when a glyph in the table is not seven rows of five bits.
    """
    font: Dict[str, List[int]] = {}
    for character in _font_keys():
        glyph = GENERATED_FONT.get(character)
        if glyph is None:
            raise ValueError(f"font table has no glyph for {character!r}")
        if len(glyph) != 7:
            raise ValueError(f"glyph {character!r} has {len(glyph)} rows, expected 7")
        for row in glyph:
            if not 0 <= row <= 0x1F:
                raise ValueError(f"glyph {character!r} has an out-of-range row {row:#04x}")
        font[character] = list(glyph)
    return font


#: The built-in font rendered as ASCII art - handy for review and for tests that
#: check the art parser against the table.
GENERATED_ART = ""



# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class GpioBackend:
    """Common interface every GPIO backend implements."""

    name = "none"

    def setup(self, pin: int, mode: str, bias: Optional[str] = None) -> None:
        """Configure a pin.

        Args:
            pin: BCM pin number.
            mode: one of :data:`MODES`.
            bias: ``up``, ``down`` or ``None``.
        """
        raise NotImplementedError

    def write(self, pin: int, value: int) -> None:
        """Drive an output pin.

        Args:
            pin: BCM pin number.
            value: 0 or 1.
        """
        raise NotImplementedError

    def read(self, pin: int) -> int:
        """Read an input pin.

        Args:
            pin: BCM pin number.

        Returns:
            0 or 1.
        """
        raise NotImplementedError

    def cleanup(self) -> None:
        """Release every pin this backend configured."""


class SimulatedBackend(GpioBackend):
    """No-hardware backend: keeps pin state in memory and logs transitions."""

    name = "simulate"

    def __init__(self, logger: Optional[Logger] = None, verbose: bool = False) -> None:
        """Create the simulated backend.

        Args:
            logger: optional logger for transitions.
            verbose: print transitions to stdout.
        """
        self.logger = logger
        self.verbose = verbose
        self.state: Dict[int, int] = {}
        self.modes: Dict[int, str] = {}
        self.history: List[Tuple[float, int, int]] = []

    def setup(self, pin: int, mode: str, bias: Optional[str] = None) -> None:
        """Record the pin configuration."""
        del bias
        self.modes[pin] = mode
        self.state.setdefault(pin, 0)

    def write(self, pin: int, value: int) -> None:
        """Record a write."""
        value = 1 if value else 0
        if self.state.get(pin) != value:
            self.history.append((time.time(), pin, value))
            if len(self.history) > 512:
                del self.history[:256]
        self.state[pin] = value
        if self.verbose:
            print(f"  [simulate] pin {pin:>2} -> {'HIGH' if value else 'LOW'}")
        if self.logger is not None:
            self.logger.debug("simulated pin %s -> %s", pin, value)

    def read(self, pin: int) -> int:
        """Return the stored level (0 unless a test sets it)."""
        return self.state.get(pin, 0)

    def cleanup(self) -> None:
        """Nothing to release in simulation."""


class SysfsBackend(GpioBackend):
    """``/sys/class/gpio`` backend, works on most Linux kernels."""

    name = "sysfs"

    def __init__(self, logger: Optional[Logger] = None) -> None:
        """Create the backend and check that sysfs GPIO is usable."""
        self.logger = logger
        self.exported: List[int] = []
        self.base = SYSFS_GPIO
        self.available = (self.base / "export").exists()
        self.holds_export_lock = False

    def _export(self, pin: int) -> bool:
        """Export a pin if needed.

        Args:
            pin: BCM pin number.

        Returns:
            True when the pin directory exists afterwards.
        """
        directory = self.base / f"gpio{pin}"
        if directory.is_dir():
            return True
        try:
            with (self.base / "export").open("w") as handle:
                handle.write(str(pin))
            self.exported.append(pin)
            for _ in range(20):
                if directory.is_dir():
                    return True
                time.sleep(0.05)
        except OSError as exc:
            if self.logger is not None:
                self.logger.error("cannot export GPIO %s: %s", pin, exc)
            return False
        return directory.is_dir()

    def setup(self, pin: int, mode: str, bias: Optional[str] = None) -> None:
        """Export the pin and set its direction."""
        del bias
        if not self._export(pin):
            raise RuntimeError(f"GPIO {pin} could not be exported")
        direction = "out" if mode == "out" else "in"
        try:
            with (self.base / f"gpio{pin}" / "direction").open("w") as handle:
                handle.write(direction)
            if direction == "in" and mode != "in":
                with (self.base / f"gpio{pin}" / "edge").open("w") as handle:
                    handle.write(mode)
        except OSError as exc:
            raise RuntimeError(f"cannot configure GPIO {pin}: {exc}") from exc

    def write(self, pin: int, value: int) -> None:
        """Write a value to the pin."""
        try:
            with (self.base / f"gpio{pin}" / "value").open("w") as handle:
                handle.write("1" if value else "0")
        except OSError as exc:
            raise RuntimeError(f"cannot write GPIO {pin}: {exc}") from exc

    def read(self, pin: int) -> int:
        """Read the pin value."""
        try:
            return int((self.base / f"gpio{pin}" / "value").read_text().strip())
        except (OSError, ValueError):
            return 0

    def cleanup(self) -> None:
        """Unexport the pins this backend exported."""
        for pin in self.exported:
            try:
                with (self.base / "unexport").open("w") as handle:
                    handle.write(str(pin))
            except OSError:
                pass
        self.exported.clear()


class PythonLibBackend(GpioBackend):
    """Backend over ``lgpio`` or ``RPi.GPIO``, if either is installed."""

    name = "python-lib"

    def __init__(self, logger: Optional[Logger] = None) -> None:
        """Probe for a usable library."""
        self.logger = logger
        self.module: Any = None
        self.kind = ""
        self.handle: Any = None
        try:
            import lgpio  # type: ignore

            self.module = lgpio
            self.kind = "lgpio"
        except ImportError:
            try:
                import RPi.GPIO as gpio  # type: ignore

                self.module = gpio
                self.kind = "rpi"
                gpio.setwarnings(False)
                gpio.setmode(gpio.BCM)
            except ImportError:
                self.module = None

    @property
    def available(self) -> bool:
        """True when a library was found."""
        return self.module is not None

    def setup(self, pin: int, mode: str, bias: Optional[str] = None) -> None:
        """Configure the pin through the library."""
        if self.kind == "rpi":
            if mode == "out":
                self.module.setup(pin, self.module.OUT)
            else:
                pull = self.module.PUD_UP if bias == "up" else (
                    self.module.PUD_DOWN if bias == "down" else self.module.PUD_OFF)
                edge = {"in": None, "rising": self.module.RISING,
                        "falling": self.module.FALLING,
                        "both": self.module.BOTH}.get(mode)
                self.module.setup(pin, self.module.IN, pull_up_down=pull)
                if edge is not None:
                    self.module.add_event_detect(pin, edge)
            return
        if self.handle is None:
            self.handle = self.module.gpiochip_open(0)
        flags = 0
        if mode == "out":
            self.module.gpio_claim_output(self.handle, pin, 0)
            return
        if bias == "up":
            flags = getattr(self.module, "SET_PULL_UP", 0)
        elif bias == "down":
            flags = getattr(self.module, "SET_PULL_DOWN", 0)
        self.module.gpio_claim_input(self.handle, pin, flags)

    def write(self, pin: int, value: int) -> None:
        """Drive the pin."""
        if self.kind == "rpi":
            self.module.output(pin, 1 if value else 0)
        else:
            self.module.gpio_write(self.handle, pin, 1 if value else 0)

    def read(self, pin: int) -> int:
        """Read the pin."""
        if self.kind == "rpi":
            return int(self.module.input(pin))
        if self.handle is None:
            return 0
        return int(self.module.gpio_read(self.handle, pin))

    def cleanup(self) -> None:
        """Release the pins."""
        if self.kind == "rpi":
            self.module.cleanup()
        elif self.handle is not None:
            self.module.gpiochip_close(self.handle)
            self.handle = None


GENERATED_ART = font_to_art(complete_font())


def detect_gpio(logger: Optional[Logger] = None, force_simulate: bool = False,
                verbose: bool = False) -> Tuple[GpioBackend, str]:
    """Return the best available GPIO backend.

    Args:
        logger: optional logger.
        force_simulate: skip the hardware backends entirely.
        verbose: print every transition when the simulated backend is chosen.

    Returns:
        A ``(backend, note)`` pair; the note explains the choice.
    """
    if force_simulate:
        return SimulatedBackend(logger, verbose), "simulation forced with --simulate"

    library = PythonLibBackend(logger)
    if library.available:
        return library, f"using {library.kind}"

    sysfs = SysfsBackend(logger)
    if sysfs.available and os.access(sysfs.base / "export", os.W_OK):
        return sysfs, "using /sys/class/gpio"

    if sysfs.available:
        return SimulatedBackend(logger, verbose), (
            "GPIO sysfs is present but not writable - run as root for real pins, "
            "continuing in simulation")

    return SimulatedBackend(logger, verbose), (
        "no GPIO hardware on this host (install python-lgpio or run on a single "
        "board computer) - continuing in simulation")


# --------------------------------------------------------------------------- #
# Pins, patterns and buttons
# --------------------------------------------------------------------------- #
@dataclass
class LedPattern:
    """A named blink pattern: a list of ``(level, seconds)`` steps."""

    name: str
    description: str
    steps: List[Tuple[int, float]]

    def as_dict(self) -> Dict[str, Any]:
        """Return the pattern as a plain dictionary.

        Returns:
            The dictionary.
        """
        return {"name": self.name, "description": self.description,
                "steps": [{"level": level, "seconds": seconds}
                          for level, seconds in self.steps]}


def builtin_patterns(blink_interval: float = 0.5) -> Dict[str, LedPattern]:
    """Build the standard set of LED patterns.

    Args:
        blink_interval: the configured base blink interval in seconds.

    Returns:
        A mapping of pattern name to :class:`LedPattern`.
    """
    unit = max(0.05, float(blink_interval))
    return {
        "off": LedPattern("off", "always dark", [(0, 0.0)]),
        "on": LedPattern("on", "steady light", [(1, 0.0)]),
        "heartbeat": LedPattern("heartbeat", "the deck is alive: two quick pulses, then a pause", [
            (1, 0.08), (0, 0.12), (1, 0.08), (0, unit * 2),
        ]),
        "slow": LedPattern("slow", "idle but awake", [(1, unit), (0, unit)]),
        "fast": LedPattern("fast", "activity: capture, scan or replay running", [
            (1, unit / 4), (0, unit / 4),
        ]),
        "strobe": LedPattern("strobe", "something is wrong: continuous strobing", [
            (1, unit / 6), (0, unit / 6),
        ]),
        "sos": LedPattern("sos", "Morse SOS - press panic or call for help", [
            (1, 0.15), (0, 0.15), (1, 0.15), (0, 0.15), (1, 0.15), (0, 0.45),
            (1, 0.45), (0, 0.15), (1, 0.45), (0, 0.15), (1, 0.45), (0, 0.45),
            (1, 0.15), (0, 0.15), (1, 0.15), (0, 0.15), (1, 0.15), (0, 1.2),
        ]),
        "double": LedPattern("double", "two flashes: a notification arrived", [
            (1, 0.1), (0, 0.2), (1, 0.1), (0, unit * 3),
        ]),
        "breathe": LedPattern("breathe", "soft fade, for a deck on a desk", [
            (1, unit / 5), (0, unit / 5), (1, unit / 4), (0, unit / 4),
            (1, unit / 3), (0, unit / 3), (1, unit / 4), (0, unit / 4),
            (1, unit / 5), (0, unit / 5),
        ]),
        "alert": LedPattern("alert", "an alert was raised on the status LED", [
            (1, 0.06), (0, 0.06), (1, 0.06), (0, 0.06), (1, 0.06), (0, 0.9),
        ]),
        "recording": LedPattern("recording", "capture in progress: a slow double pulse", [
            (1, 0.3), (0, 0.4), (1, 0.3), (0, unit * 2),
        ]),
    }


class Pin:
    """A single GPIO pin with a timed-pulse helper.

    Args:
        number: BCM pin number.
        backend: the backend to drive it through.
        logger: optional logger.
        mode: ``out`` or one of the input edge modes.
        bias: ``up``, ``down`` or ``None``.
    """

    def __init__(self, number: int, backend: GpioBackend, logger: Optional[Logger] = None,
                 mode: str = "out", bias: Optional[str] = None) -> None:
        """Configure the pin."""
        self.number = int(number)
        self.backend = backend
        self.logger = logger
        self.mode = mode
        self.bias = bias
        self.value = 0
        self.backend.setup(self.number, mode, bias)

    def write(self, value: int) -> None:
        """Set the pin level.

        Args:
            value: 0 or 1.
        """
        value = 1 if value else 0
        if value != self.value:
            self.backend.write(self.number, value)
            self.value = value

    def read(self) -> int:
        """Read the pin level.

        Returns:
            0 or 1.
        """
        return self.backend.read(self.number)

    def pulse(self, seconds: float) -> None:
        """Drive the pin high for a moment.

        Args:
            seconds: how long to stay high.
        """
        self.write(1)
        time.sleep(max(0.0, seconds))
        self.write(0)

    def blink(self, on_seconds: float = 0.1, off_seconds: float = 0.1,
              times: int = 1) -> None:
        """Blink the pin a number of times.

        Args:
            on_seconds: time spent high.
            off_seconds: time spent low.
            times: number of pulses.
        """
        for _ in range(max(1, times)):
            self.write(1)
            time.sleep(max(0.0, on_seconds))
            self.write(0)
            time.sleep(max(0.0, off_seconds))

    def deinit(self) -> None:
        """Drive the pin low before releasing it."""
        try:
            self.write(0)
        except Exception:  # noqa: BLE001 - releasing must never raise
            pass


class Button:
    """A debounced button with short, long and double press detection.

    Args:
        pin: BCM pin number.
        backend: the backend to read it from.
        logger: optional logger.
        active_low: True when pressing pulls the pin to ground (the usual
            wiring with a pull-up resistor).
        bounce_s: debounce window in seconds.
        long_press_s: how long counts as a long press.
        double_gap_s: maximum gap between presses for a double press.
    """

    def __init__(self, pin: int, backend: GpioBackend, logger: Optional[Logger] = None,
                 active_low: bool = True, bounce_s: float = 0.05,
                 long_press_s: float = 2.0, double_gap_s: float = 0.4) -> None:
        """Configure the button pin."""
        self.pin = Pin(int(pin), backend, logger, mode="in",
                       bias="up" if active_low else "down")
        self.logger = logger
        self.active_low = active_low
        self.bounce_s = bounce_s
        self.long_press_s = long_press_s
        self.double_gap_s = double_gap_s
        self._press_started: Optional[float] = None
        self._last_release: Optional[float] = None
        self._last_press_time: Optional[float] = None
        self._pending_double = False

    def pressed(self) -> bool:
        """Return True while the button is held down.

        Returns:
            True when pressed.
        """
        level = self.pin.read()
        return (level == 0) if self.active_low else (level == 1)

    def wait_for_release(self, timeout: float = 5.0) -> None:
        """Block until the button is released.

        Args:
            timeout: give up after this many seconds.
        """
        deadline = time.time() + timeout
        while self.pressed() and time.time() < deadline:
            time.sleep(0.01)

    def poll(self) -> Optional[str]:
        """Check for a press and classify it.

        Call this in a loop; the method is non-blocking.

        Returns:
            ``"short"``, ``"long"`` or ``"double"`` when an event completed,
            otherwise ``None``.
        """
        now = time.time()
        if self.pressed():
            if self._press_started is None:
                if self._last_release is not None and now - self._last_release < self.bounce_s:
                    # Contact bounce: treat as part of the previous press
                    self._press_started = None
                    return None
                self._press_started = now
                if self._last_release is not None and now - self._last_release <= self.double_gap_s:
                    self._pending_double = True
            if now - (self._press_started or now) >= self.long_press_s:
                self._press_started = None
                self._pending_double = False
                self._last_release = now
                if self.logger is not None:
                    self.logger.info("button %s: long press", self.pin.number)
                return "long"
            return None

        if self._press_started is not None:
            held = now - self._press_started
            self._press_started = None
            self._last_release = now
            if held < self.bounce_s:
                return None
            if self._pending_double:
                self._pending_double = False
                if self.logger is not None:
                    self.logger.info("button %s: double press", self.pin.number)
                return "double"
            if self.logger is not None:
                self.logger.info("button %s: short press (%.2fs)", self.pin.number, held)
            return "short"
        return None

    def wait(self, timeout: Optional[float] = None, poll_interval: float = 0.02,
             inject: Optional[Callable[[], Optional[str]]] = None) -> Optional[str]:
        """Block until a press completes.

        Args:
            timeout: stop after this many seconds.
            poll_interval: how often to sample.
            inject: optional callback returning a synthetic event (used by
                ``--simulate`` so the handler can be tested without hardware).

        Returns:
            The event name, or ``None`` on timeout.
        """
        deadline = None if timeout is None else time.time() + timeout
        while True:
            event = self.poll()
            if event is not None:
                return event
            if inject is not None:
                event = inject()
                if event is not None:
                    return event
            if deadline is not None and time.time() >= deadline:
                return None
            time.sleep(poll_interval)

    def deinit(self) -> None:
        """Release the button pin."""
        self.pin.deinit()


# --------------------------------------------------------------------------- #
# I2C + SSD1306
# --------------------------------------------------------------------------- #
class I2CError(RuntimeError):
    """Raised when the I2C bus cannot be used."""


class I2CDevice:
    """A bare file-descriptor I2C device (no smbus dependency).

    Args:
        bus: I2C bus number (1 is the usual Raspberry Pi bus).
        address: 7-bit device address.

    Raises:
        I2CError: when the device node cannot be opened or claimed.
    """

    def __init__(self, bus: int = 1, address: int = 0x3C) -> None:
        """Open the bus and claim the address."""
        self.path = I2C_DEV_ROOT / f"i2c-{bus}"
        self.address = address
        try:
            self.fd = os.open(self.path, os.O_RDWR)
        except OSError as exc:
            raise I2CError(
                f"cannot open {self.path}: {exc} (is I2C enabled? try: sudo "
                f"raspi-config nonint do_i2c 0)") from exc
        try:
            fcntl.ioctl(self.fd, I2C_SLAVE, address)
        except OSError as exc:
            os.close(self.fd)
            raise I2CError(f"no device at 0x{address:02X} on {self.path}: {exc}") from exc

    def write(self, data: bytes) -> int:
        """Write bytes to the device.

        Args:
            data: the payload.

        Returns:
            The number of bytes written.
        """
        try:
            return os.write(self.fd, data)
        except OSError as exc:
            raise I2CError(f"write to 0x{self.address:02X} failed: {exc}") from exc

    def read(self, length: int) -> bytes:
        """Read bytes from the device.

        Args:
            length: how many bytes to read.

        Returns:
            The data read.
        """
        try:
            return os.read(self.fd, length)
        except OSError as exc:
            raise I2CError(f"read from 0x{self.address:02X} failed: {exc}") from exc

    def close(self) -> None:
        """Close the device."""
        try:
            os.close(self.fd)
        except OSError:
            pass

    def __enter__(self) -> "I2CDevice":
        """Context manager entry."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Context manager exit."""
        self.close()


def scan_i2c(bus: int = 1, first: int = 0x03, last: int = 0x77) -> List[int]:
    """Probe an I2C bus for responding addresses.

    Args:
        bus: the bus number.
        first: first address to probe.
        last: last address to probe.

    Returns:
        The addresses that acknowledged, ascending.
    """
    found: List[int] = []
    path = I2C_DEV_ROOT / f"i2c-{bus}"
    if not path.exists():
        return found
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return found
    try:
        for address in range(first, last + 1):
            try:
                fcntl.ioctl(fd, I2C_SLAVE, address)
                os.write(fd, b"\x00")
                found.append(address)
            except OSError:
                continue
    finally:
        os.close(fd)
    return found


class SSDDummy:
    """In-memory stand-in for :class:`SSD1306` used when no panel is attached."""

    def __init__(self, width: int = 128, height: int = 64) -> None:
        """Create the dummy display."""
        self.width = width
        self.height = height
        self.buffer = bytearray(width * height // 8)
        self.addresses: List[int] = []

    def command(self, *values: int) -> None:
        """Record a command."""
        del values

    def data(self, values: Iterable[int]) -> None:
        """Record data writes."""
        del values

    def display(self) -> None:
        """Push the buffer (a no-op in the dummy)."""

    def clear(self) -> None:
        """Clear the buffer."""
        self.buffer = bytearray(len(self.buffer))

    def text(self, x: int, y: int, message: str, scale: int = 1, invert: bool = False) -> None:
        """Draw text into the buffer.

        Args:
            x: column.
            y: page (8-pixel row).
            message: the text.
            scale: integer magnification.
            invert: draw dark-on-light.
        """
        draw_text(self, x, y, message, scale, invert)

    def close(self) -> None:
        """Nothing to release."""


class SSD1306(SSDDummy):
    """A dependency-free SSD1306 (and SH1106-compatible) OLED driver.

    Args:
        bus: I2C bus number.
        address: I2C address (0x3C or 0x3D).
        width: panel width in pixels.
        height: panel height in pixels (32 or 64).
        controller: ``ssd1306`` or ``sh1106`` (the SH1106 has a 132-column RAM
            and needs a 2-pixel offset).
    """

    COLUMN_OFFSET = 0x00
    PAGES = 8
    CHARGE_PUMP_ON = 0x14
    CHARGE_PUMP_OFF = 0x10

    def __init__(self, bus: int = 1, address: int = 0x3C, width: int = 128,
                 height: int = 64, controller: str = "ssd1306") -> None:
        """Open the panel and run its initialisation sequence."""
        super().__init__(width, height)
        self.device = I2CDevice(bus, address)
        self.controller = controller.lower()
        if self.controller == "sh1106":
            self.COLUMN_OFFSET = 0x02
        self.pages = height // 8
        self.buffer = bytearray(width * self.pages)
        self._initialise()

    def _initialise(self) -> None:
        """Send the standard SSD1306 power-on sequence."""
        multiplex = self.height - 1
        com_pins = 0x12 if self.height == 64 else 0x02
        sequence = [
            SSD1306_DISPLAY_OFF,
            SSD1306_SET_DISPLAY_CLOCK_DIV, 0x80,
            SSD1306_SET_MULTIPLEX, multiplex,
            SSD1306_SET_DISPLAY_OFFSET, 0x00,
            SSD1306_SET_START_LINE | 0x00,
            SSD1306_CHARGE_PUMP, self.CHARGE_PUMP_ON,
            SSD1306_MEMORY_MODE, 0x00,
            SSD1306_SEG_REMAP | 0x01,
            SSD1306_COM_SCAN_DEC,
            SSD1306_SET_COM_PINS, com_pins,
            SSD1306_SET_CONTRAST, 0xCF,
            SSD1306_SET_PRECHARGE, 0xF1,
            SSD1306_SET_VCOM_DETECT, 0x40,
            SSD1306_DISPLAY_ALL_ON_RESUME,
            SSD1306_NORMAL_DISPLAY,
            SSD1306_DISPLAY_ON,
        ]
        self.command(*sequence)

    def command(self, *values: int) -> None:
        """Send control bytes (each prefixed with 0x00).

        Args:
            *values: command bytes.
        """
        payload = b"".join(bytes([0x00, value & 0xFF]) for value in values)
        for start in range(0, len(payload), 32):
            self.device.write(payload[start:start + 32])

    def data(self, values: Iterable[int]) -> None:
        """Send pixel data (prefixed with 0x40).

        Args:
            values: pixel bytes.
        """
        payload = bytes([0x40]) + bytes(bytearray(values))
        for start in range(0, len(payload) - 1, 32):
            self.device.write(payload[start:start + 32])

    def display(self) -> None:
        """Flush the framebuffer to the panel."""
        for page in range(self.pages):
            self.command(0xB0 + page)
            self.command(SSD1306_SET_LOW_COLUMN | (self.COLUMN_OFFSET & 0x0F))
            self.command((SSD1306_SET_HIGH_COLUMN | ((self.COLUMN_OFFSET >> 4) & 0x0F)))
            self.data(self.buffer[page * self.width:(page + 1) * self.width])

    def close(self) -> None:
        """Blank the panel and close the bus."""
        try:
            self.clear()
            self.display()
        finally:
            self.device.close()


def draw_text(display: Any, x: int, y: int, message: str, scale: int = 1,
              invert: bool = False) -> None:
    """Draw a string into a display buffer using the built-in font.

    Args:
        display: any object exposing ``buffer``, ``width`` and ``pages``.
        x: starting column.
        y: starting page (each page is 8 pixels tall).
        message: the text to draw (non-ASCII characters become ``?``).
        scale: integer magnification.
        invert: invert the pixels of this string.
    """
    font = complete_font()
    scale = max(1, int(scale))
    cursor = int(x)
    for character in message:
        glyph = font.get(character) or font.get("?") or [0] * 7
        for column in range(5):
            bits = 0
            for row in range(7):
                if glyph[row] & (1 << (4 - column)):
                    bits |= 1 << row
            if invert:
                bits = ~bits & 0x7F
            for repeat in range(scale):
                position = (int(y) * display.width) + cursor + (column * scale) + repeat
                if 0 <= position < len(display.buffer):
                    display.buffer[position] = bits
        # blank the inter-character column
        for repeat in range(scale):
            position = (int(y) * display.width) + cursor + (5 * scale) + repeat
            if 0 <= position < len(display.buffer):
                display.buffer[position] = 0x7F if invert else 0x00
        cursor += 6 * scale
        if cursor + 6 * scale > display.width:
            break


def draw_text_scaled(display: Any, x: int, y: int, message: str, scale: int = 1) -> None:
    """Draw text at a whole-pixel (not page) vertical position.

    The 5x7 font is page aligned, so a scale of 2 needs the glyph shifted; this
    helper handles that by writing through a temporary page buffer.

    Args:
        display: the display object.
        x: column.
        y: page.
        message: the text.
        scale: magnification.
    """
    if scale <= 1:
        draw_text(display, x, y, message, 1)
        return
    # Collect the glyph columns once, then blit them twice as wide and twice as tall
    font = complete_font()
    cursor = int(x)
    for character in message:
        glyph = font.get(character) or font.get("?") or [0] * 7
        for column in range(5):
            bits = 0
            for row in range(7):
                if glyph[row] & (1 << (4 - column)):
                    bits |= 1 << row
            target = int(y)
            doubled = 0
            # Expand each of the 7 rows into two rows for 14-pixel tall glyphs
            for row in range(7):
                if bits & (1 << row):
                    doubled |= (1 << (row * 2)) | (1 << (row * 2 + 1))
            for block in (target, target + 1):
                if 0 <= block < display.pages:
                    for repeat in range(2):
                        position = block * display.width + cursor + column * 2 + repeat
                        if 0 <= position < len(display.buffer):
                            display.buffer[position] = doubled & 0xFF
        cursor += 12
        if cursor + 12 > display.width:
            break


def make_display(config: Any = None, logger: Optional[Logger] = None,
                 simulate: bool = False) -> Tuple[Any, str]:
    """Create the configured OLED display, falling back to a dummy.

    Args:
        config: optional loaded cyberdeck configuration.
        logger: optional logger.
        simulate: force the in-memory display.

    Returns:
        A ``(display, note)`` pair.
    """
    width, height, bus, address = 128, 64, 1, 0x3C
    controller = "ssd1306"
    if config is not None:
        address_text = str(config.get("gpio.oled_i2c_address", "0x3C"))
        try:
            address = int(address_text, 16) if address_text.lower().startswith("0x") \
                else int(address_text)
        except ValueError:
            address = 0x3C
        bus = int(config.get("gpio.oled_bus", 1) or 1)
        controller = str(config.get("gpio.oled_controller", "ssd1306") or "ssd1306")
    if simulate:
        return SSDDummy(width, height), "using the in-memory display (--simulate)"

    if not (I2C_DEV_ROOT / f"i2c-{bus}").exists():
        return SSDDummy(width, height), (
            f"no I2C device at {I2C_DEV_ROOT}/i2c-{bus} - enable I2C (raspi-config) "
            "or run with --simulate")
    try:
        display = SSD1306(bus=bus, address=address, width=width, height=height,
                          controller=controller)
    except I2CError as exc:
        return SSDDummy(width, height), f"{exc} - continuing with the in-memory display"
    if logger is not None:
        logger.debug("opened %s panel at 0x%02X on i2c-%s", controller, address, bus)
    return display, f"using {controller} at 0x{address:02X} on i2c-{bus}"


# --------------------------------------------------------------------------- #
# Reporting helpers
# --------------------------------------------------------------------------- #
def backends_report(logger: Optional[Logger] = None) -> Dict[str, Any]:
    """Describe every backend and what it can see.

    Args:
        logger: optional logger.

    Returns:
        A dictionary with one entry per backend.
    """
    library = PythonLibBackend(logger)
    sysfs = SysfsBackend(logger)
    report: Dict[str, Any] = {
        "version": VERSION,
        "python_library": {
            "available": library.available,
            "kind": library.kind or None,
            "hint": "sudo pacman -S python-lgpio   # or pip install RPi.GPIO",
        },
        "sysfs": {
            "available": sysfs.available,
            "writable": os.access(sysfs.base / "export", os.W_OK) if sysfs.available else False,
            "path": str(sysfs.base),
        },
        "i2c": {
            "buses": [str(path.name) for path in sorted(I2C_DEV_ROOT.glob("i2c-*"))],
            "devices": {path.name: scan_i2c(int(path.name.split("-")[1]))
                        for path in sorted(I2C_DEV_ROOT.glob("i2c-*"))},
        },
        "simulation_available": True,
    }
    return report


def selftest(logger: Logger, pin_number: int = 17, oled: bool = True) -> int:
    """Exercise the GPIO layer end to end.

    Args:
        logger: shared logger.
        pin_number: pin to blink.
        oled: also test the display path.

    Returns:
        Process exit code (0 when everything worked).
    """
    problems = 0
    backend, note = detect_gpio(logger)
    logger.info("backend: %s (%s)", backend.name, note)

    logger.info("blinking pin %s three times", pin_number)
    try:
        pin = Pin(pin_number, backend, logger)
        for _ in range(3):
            pin.write(1)
            time.sleep(0.1)
            pin.write(0)
            time.sleep(0.1)
        pin.deinit()
        logger.ok("pin %s toggled cleanly", pin_number)
    except Exception as exc:  # noqa: BLE001 - a selftest reports, never raises
        logger.error("pin test failed: %s", exc)
        problems += 1

    logger.info("parsing the built-in font")
    try:
        font = complete_font()
        missing = [chr(code) for code in range(FONT_FIRST, FONT_LAST + 1)
                   if chr(code) not in font]
        if missing:
            logger.error("font is missing: %s", "".join(missing))
            problems += 1
        else:
            logger.ok("font covers all %d printable ASCII glyphs", len(font))
    except ValueError as exc:
        logger.error("font is malformed: %s", exc)
        problems += 1

    if oled:
        logger.info("testing the display")
        display, display_note = make_display(None, logger)
        logger.info("display: %s", display_note)
        try:
            display.clear()
            display.text(0, 0, "SELFTEST")
            display.text(0, 2, "cyberdeck")
            display.text(0, 4, "gpio layer ok")
            display.display()
            logger.ok("display buffer written")
        except Exception as exc:  # noqa: BLE001
            logger.error("display test failed: %s", exc)
            problems += 1
        finally:
            display.close()

    backend.cleanup()
    if problems:
        logger.warn("%d problem(s) found", problems)
        return 1
    logger.ok("GPIO layer healthy")
    return 0


def show_glyph(character: str) -> int:
    """Print a font glyph as ASCII art.

    Args:
        character: the character to render (first character is used).

    Returns:
        Process exit code.
    """
    font = complete_font()
    glyph = font.get(character[:1]) or font.get("?")
    if glyph is None:
        print(f"no glyph for {character[:1]!r}")
        return 1
    print(f"'{character[:1]}' (0x{ord(character[:1]):02X})")
    for row in glyph:
        print("  " + "".join("#" if row & (1 << (4 - column)) else "."
                             for column in range(5)))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the shared GPIO helper command line.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(
        prog="cybergpio.py",
        description="GPIO, I2C and OLED support shared by the cyberdeck gpio tools",
        epilog="authorised use only - see docs/LEGAL.md")
    parser.add_argument("--version", action="version", version=f"cybergpio {VERSION}")
    parser.add_argument("--detect", action="store_true",
                        help="report the available backends and I2C devices")
    parser.add_argument("--i2c-scan", action="store_true", help="scan the I2C buses")
    parser.add_argument("--bus", type=int, default=1, help="I2C bus to scan (default 1)")
    parser.add_argument("--selftest", action="store_true", help="exercise pins and the OLED")
    parser.add_argument("--pin", type=int, default=17, help="pin used by --selftest")
    parser.add_argument("--font", metavar="CHAR", default="",
                        help="print a font glyph as ASCII art")
    parser.add_argument("--dump-font", action="store_true",
                        help="render the whole built-in font as ASCII art")
    parser.add_argument("--simulate", action="store_true", help="force the no-hardware backend")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    args = parser.parse_args(argv)

    logger = Logger("cybergpio", "INFO", quiet=args.quiet)
    if args.font:
        return show_glyph(args.font)
    if args.dump_font:
        print(f"# built-in font, {len(complete_font())} glyphs, "
              f"{FONT_FIRST}-{FONT_LAST} (space to tilde)")
        print(GENERATED_ART)
        return 0

    if args.i2c_scan:
        devices = scan_i2c(args.bus)
        if args.json:
            print(json.dumps({"bus": args.bus, "devices": devices}))
        else:
            if not devices:
                print(f"no devices responded on i2c-{args.bus}")
                return 3
            print(f"devices on i2c-{args.bus}: " + ", ".join(f"0x{a:02X}" for a in devices))
        return 0

    if args.selftest:
        return selftest(logger, args.pin)

    report = backends_report(logger)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    if not args.detect:
        parser.print_help()
        print()
    print(f"cybergpio {VERSION}")
    print(f"  python library : {report['python_library']['kind'] or 'none'}")
    print(f"  sysfs          : {'yes' if report['sysfs']['available'] else 'no'}"
          f" (writable: {report['sysfs']['writable']})")
    print(f"  i2c buses      : {', '.join(report['i2c']['buses']) or 'none'}")
    for bus, devices in report["i2c"]["devices"].items():
        print(f"    {bus}: " + (", ".join(f"0x{a:02X}" for a in devices) or "nothing found"))
    backend, note = detect_gpio(logger, force_simulate=args.simulate)
    print(f"  selected       : {backend.name} ({note})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
