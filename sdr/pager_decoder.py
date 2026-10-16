#!/usr/bin/env python3
"""
sdr/pager_decoder.py - POCSAG pager decoder (receive only).
===========================================================

Description
-----------
Decodes POCSAG paging traffic from an RTL-SDR. POCSAG is a two-level FSK paging
protocol and is still widely used for on-site pagers, fire/ambulance callout
and industrial alerting. The module implements the whole chain itself:

* capture through ``rtl_fm`` (or replay of a recorded raw audio stream, or a
  text file of bits), so a decoder run can be reproduced afterwards
* DC-blocking and per-bit slicing of the demodulated baseband at 512, 1200 or
  2400 baud, with automatic bit-phase search against the POCSAG sync codeword
* BCH(31,21) error correction (two bit errors per codeword) and the even-parity
  bit, so noisy transmissions still decode
* batch/frame parsing: address codewords give the capcode, the two function
  bits select the message type, and message codewords accumulate numeric (BCD)
  or alphanumeric (7-bit ASCII) payloads until the next address or idle codeword
* capcode labelling from ``data/pager_capcodes.json`` so a report says
  "Site-2 fire panel" instead of "1234567"
* JSONL/CSV output under ``captures/pager/``, events in the shared database and
  an optional Rich live table

Paging traffic is not private in the cryptographic sense and can carry personal
data, so treat captures with the same care as any other customer data.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: rtl-sdr (rtl_fm, optional - a recorded stream works without it);
              optional: rich (live table)
Licence     : MIT - receive-only (see docs/LEGAL.md)

Usage
-----
    sudo ./pager_decoder.py --frequency 153.35 --duration 120 --live
    ./pager_decoder.py --input recording.raw --json
    ./pager_decoder.py --bits capture.bits --baud 512
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "lib",
    Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")) / "lib",
]
for _candidate in _LIB_CANDIDATES:
    if (_candidate / "cyberlib.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

try:
    from cyberlib import Config, Database, Hardware, Logger, colour, now_iso  # type: ignore
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: POCSAG sync codeword, transmitted at the start of every batch
SYNC_WORD = 0x7CD215D8
#: Idle codeword, used to fill the rest of a batch
IDLE_WORD = 0x7A89C197
#: BCH(31,21) generator polynomial used by POCSAG (x^10+x^9+x^8+x^6+x^5+x^3+1)
BCH_POLY = 0x769
#: Numeric (BCD) character set used by POCSAG numeric messages
NUMERIC_CHARS = "0123456789*U -)("
#: Function bit meanings for alphanumeric messaging (common industry usage)
FUNCTION_LABELS = {
    0: "numeric",
    1: "alphanumeric/spare",
    2: "spare",
    3: "alphanumeric",
}


@dataclass
class PagerMessage:
    """One decoded pager message."""

    capcode: int
    function: int
    mode: str
    text: str
    received: str = field(default_factory=now_iso)
    bit_errors: int = 0
    codewords: int = 0
    frequency_hz: int = 0
    baud: int = 1200
    label: str = ""
    confident: bool = True

    @property
    def display(self) -> str:
        """A one-line rendering of the message."""
        who = f"{self.capcode}"
        if self.label:
            who = f"{self.capcode} ({self.label})"
        return f"{who} [{self.mode}] {self.text}"

    def as_dict(self) -> Dict[str, Any]:
        """Return the message as a plain dictionary."""
        return {
            "capcode": self.capcode,
            "label": self.label,
            "function": self.function,
            "mode": self.mode,
            "text": self.text,
            "received": self.received,
            "bit_errors": self.bit_errors,
            "codewords": self.codewords,
            "frequency_hz": self.frequency_hz,
            "baud": self.baud,
            "confident": self.confident,
        }


# --------------------------------------------------------------------------- #
# BCH and codeword handling
# --------------------------------------------------------------------------- #
def bch_syndrome(codeword: int) -> int:
    """Compute the BCH syndrome of a 31-bit POCSAG codeword.

    Args:
        codeword: the 31 data+check bits (the 32nd parity bit excluded).

    Returns:
        The remainder of the codeword polynomial division; zero means the
        codeword is valid.
    """
    remainder = codeword & 0x7FFFFFFF
    for bit in range(30, 9, -1):
        if remainder & (1 << bit):
            remainder ^= BCH_POLY << (bit - 10)
    return remainder & 0x3FF


def correct_codeword(codeword: int) -> Optional[Tuple[int, int]]:
    """Correct up to two bit errors in a 31-bit POCSAG codeword.

    Args:
        codeword: the raw 31-bit codeword (parity bit excluded).

    Returns:
        A ``(corrected_codeword, errors_fixed)`` tuple, or ``None`` when the
        codeword cannot be corrected (three or more errors).
    """
    if bch_syndrome(codeword) == 0:
        return codeword, 0
    for first in range(31):
        candidate = codeword ^ (1 << first)
        if bch_syndrome(candidate) == 0:
            return candidate, 1
    for first in range(31):
        for second in range(first + 1, 31):
            candidate = codeword ^ (1 << first) ^ (1 << second)
            if bch_syndrome(candidate) == 0:
                return candidate, 2
    return None


def even_parity(value: int) -> int:
    """Return the even-parity bit for a 31-bit value.

    Args:
        value: the 31-bit codeword.

    Returns:
        The parity bit (0 or 1) so that the 32-bit word has even parity.
    """
    return bin(value).count("1") & 1


def hamming_distance(first: int, second: int) -> int:
    """Return the number of differing bits between two integers.

    Args:
        first: first value.
        second: second value.

    Returns:
        The Hamming distance.
    """
    return bin(first ^ second).count("1")


class PocsagBitDecoder:
    """Turns a stream of bits into POCSAG messages.

    The decoder is fed one bit at a time (already sliced from the demodulated
    audio) and keeps the little state machine that POCSAG needs: hunt for the
    sync codeword, then read sixteen 32-bit codewords, then expect sync again.
    """

    def __init__(self) -> None:
        """Create an idle decoder."""
        self.shift_register = 0
        self.in_sync = False
        self.codewords_into_batch = 0
        self.bit_count = 0
        self.batch_count = 0
        self.codeword_errors = 0
        self.bits_since_sync = 0
        self.bad_batches = 0
        #: The address and function bits of the most recent address codeword.
        #: POCSAG messages start at an address codeword and run on through the
        #: following message codewords - across frame boundaries - until the
        #: next address or idle codeword, so a single "current message" state is
        #: all the framing needs.
        self.current: Optional[Tuple[int, int]] = None
        self.buffers: Dict[Tuple[int, int], List[Tuple[int, int]]] = defaultdict(list)
        #: Bit index of the last codeword for each open buffer, used to expire
        #: messages that are never closed because the stream went quiet
        self.last_update: Dict[Tuple[int, int], int] = {}
        self.last_flush_reason = ""
        self.messages: List[PagerMessage] = []

    # -- bit level --------------------------------------------------------- #
    def push_bit(self, bit: int) -> List[PagerMessage]:
        """Feed one bit into the decoder.

        Args:
            bit: 0 or 1.

        Returns:
            Any messages completed by this bit (usually empty).
        """
        self.bit_count += 1
        self.bits_since_sync += 1
        self.shift_register = ((self.shift_register << 1) | (bit & 1)) & 0xFFFFFFFF
        completed: List[PagerMessage] = []

        if not self.in_sync:
            if self.bits_since_sync >= 32 and \
                    hamming_distance(self.shift_register, SYNC_WORD) <= 2:
                self.in_sync = True
                self.codewords_into_batch = 0
                self.bits_since_sync = 0
                self.batch_count += 1
                # A sync does *not* end a message: long messages continue into
                # the next batch, so the buffers stay open.
                completed.extend(self.expire_stale())
            return completed

        if self.bits_since_sync >= 32:
            self.bits_since_sync = 0
            codeword = self.shift_register
            completed.extend(self.handle_codeword(codeword))
        return completed

    # -- codeword level ---------------------------------------------------- #
    def handle_codeword(self, codeword: int) -> List[PagerMessage]:
        """Process one 32-bit codeword.

        Args:
            codeword: the received 32-bit word.

        Returns:
            Any messages completed by this codeword.
        """
        completed: List[PagerMessage] = []
        # A new batch may start here (sync at the expected position)
        if hamming_distance(codeword, SYNC_WORD) <= 2:
            self.batch_count += 1
            self.codewords_into_batch = 0
            self.bad_batches = 0
            completed.extend(self.expire_stale())
            return completed

        if hamming_distance(codeword, IDLE_WORD) <= 2:
            completed.extend(self.flush_buffers("idle"))
        else:
            data_bits = (codeword >> 1) & 0x7FFFFFFF
            parity_ok = ((bin(codeword).count("1") & 1) == 0)
            corrected = correct_codeword(data_bits)
            if corrected is None:
                # Not recoverable: abandon this batch and hunt for sync again
                self.codeword_errors += 1
                self.bad_batches += 1
                if self.bad_batches >= 2:
                    self.in_sync = False
                    self.bits_since_sync = 0
                return completed
            fixed, errors = corrected
            if not parity_ok and errors == 0:
                # Parity says corrupt but BCH says clean: trust the parity and
                # treat it as one error for reporting purposes
                errors = 1
            self.codeword_errors += errors
            completed.extend(self.handle_data_codeword(fixed, errors))

        self.codewords_into_batch += 1
        if self.codewords_into_batch >= 16:
            # End of batch: the next word must be sync again
            self.codewords_into_batch = 0
            self.in_sync = False
            self.bits_since_sync = 0
        return completed

    def handle_data_codeword(self, codeword: int, errors: int) -> List[PagerMessage]:
        """Process a corrected data codeword (address or message).

        Args:
            codeword: the corrected 31-bit codeword.
            errors: how many bits were corrected.

        Returns:
            Any messages completed by this codeword.
        """
        frame = (self.codewords_into_batch // 2) % 8
        is_address = (codeword & 0x40000000) == 0
        completed: List[PagerMessage] = []

        if is_address:
            # A new address ends the message that was in progress
            completed.extend(self.flush_buffers("new address"))
            address = (((codeword >> 12) & 0x3FFFF) << 3) | frame
            function = (codeword >> 10) & 0x3
            self.current = (address, function)
            self.buffers.setdefault((address, function), [])
            self.last_update[(address, function)] = self.bit_count
            return completed

        payload = (codeword >> 10) & 0xFFFFF
        if self.current is None:
            # A message codeword with no address before it: not ours
            return completed
        self.buffers.setdefault(self.current, []).append((payload, errors))
        self.last_update[self.current] = self.bit_count
        return completed

    def expire_stale(self) -> List[PagerMessage]:
        """Close buffers that have not been extended for two batches.

        A message is normally closed by the next address or idle codeword. If
        the transmitter stops mid-message (or the receiver went deaf) the buffer
        would otherwise stay open forever, so anything untouched for two batch
        lengths is decoded and closed.

        Returns:
            The messages closed by this expiry.
        """
        window = 16 * 32 * 2
        stale = [key for key, stamp in self.last_update.items()
                 if self.bit_count - stamp > window and self.buffers.get(key)]
        if not stale:
            return []
        completed: List[PagerMessage] = []
        for key in stale:
            entries = self.buffers.pop(key, [])
            self.last_update.pop(key, None)
            if self.current == key:
                self.current = None
            payloads = [(payload, errors) for payload, errors in entries if payload]
            if not payloads:
                continue
            address, function = key
            text, mode, confident = decode_payload(payloads, function)
            self.last_flush_reason = "stale"
            if text:
                completed.append(PagerMessage(
                    capcode=address, function=function, mode=mode, text=text,
                    bit_errors=sum(error for _payload, error in entries),
                    codewords=len(entries), confident=confident))
        return completed

    def flush_buffers(self, reason: str) -> List[PagerMessage]:
        """Close every open message buffer and decode its payload.

        Args:
            reason: why the buffers are being flushed (debugging aid).

        Returns:
            The completed messages.
        """
        completed: List[PagerMessage] = []
        for key, entries in list(self.buffers.items()):
            payloads = [(payload, errors) for payload, errors in entries if payload]
            if not payloads:
                self.buffers.pop(key, None)
                self.last_update.pop(key, None)
                continue
            address, function = key
            text, mode, confident = decode_payload(payloads, function)
            errors = sum(error for _payload, error in entries)
            if text:
                self.logger_note(reason)
                completed.append(PagerMessage(
                    capcode=address,
                    function=function,
                    mode=mode,
                    text=text,
                    bit_errors=errors,
                    codewords=len(entries),
                    confident=confident,
                ))
            self.buffers.pop(key, None)
            self.last_update.pop(key, None)
        self.current = None
        return completed

    def logger_note(self, reason: str) -> None:
        """Hook for subclasses/tests to observe flush reasons.

        Args:
            reason: the flush reason.
        """
        self.last_flush_reason = reason

# --------------------------------------------------------------------------- #
# Payload decoding
# --------------------------------------------------------------------------- #
def decode_payload(entries: Sequence[Tuple[int, int]], function: int) -> Tuple[str, str, bool]:
    """Decode the 20-bit payloads of a message.

    Args:
        entries: ``(payload, errors)`` pairs in transmission order.
        function: the function bits of the address codeword.

    Returns:
        A ``(text, mode, confident)`` tuple.
    """
    numeric = decode_numeric(entries)
    alphanumeric = decode_alphanumeric(entries)

    if function in (1, 3):
        return alphanumeric, "alphanumeric", True
    if function == 0:
        return numeric, "numeric", True

    # Function bits 2 are unassigned in the standard: decide from the content
    letters = sum(character.isalpha() for character in alphanumeric)
    if letters >= 3 and len(alphanumeric) >= len(numeric) / 2:
        return alphanumeric, "alphanumeric", True
    return numeric, "numeric", False


def decode_numeric(entries: Sequence[Tuple[int, int]]) -> str:
    """Decode the codewords as a numeric (BCD) message.

    Args:
        entries: ``(payload, errors)`` pairs.

    Returns:
        The decoded digits (the trailing filler characters are trimmed).
    """
    characters = []
    for payload, _errors in entries:
        for shift in (16, 12, 8, 4, 0):
            nibble = (payload >> shift) & 0xF
            characters.append(NUMERIC_CHARS[nibble] if nibble < len(NUMERIC_CHARS) else "?")
    return "".join(characters).rstrip()


def decode_alphanumeric(entries: Sequence[Tuple[int, int]]) -> str:
    """Decode the codewords as an alphanumeric (7-bit ASCII) message.

    Characters are packed continuously across codewords: 20 bits per codeword
    are appended to a bit buffer and consumed seven at a time.

    Args:
        entries: ``(payload, errors)`` pairs.

    Returns:
        The decoded text with the trailing fill characters trimmed.
    """
    bits: List[int] = []
    for payload, _errors in entries:
        for shift in range(19, -1, -1):
            bits.append((payload >> shift) & 1)
    text = []
    for index in range(0, len(bits) - 6, 7):
        value = 0
        for bit in bits[index:index + 7]:
            value = (value << 1) | bit
        text.append(chr(value) if 32 <= value < 127 else " ")
    return "".join(text).rstrip()


def looks_like_garbage(text: str) -> bool:
    """Heuristically decide whether a decoded message is noise.

    Args:
        text: the decoded payload.

    Returns:
        True when fewer than half of the characters are printable.
    """
    if not text:
        return True
    printable = sum(character.isprintable() and character != "\x7f" for character in text)
    return printable / len(text) < 0.5


# --------------------------------------------------------------------------- #
# Slicer
# --------------------------------------------------------------------------- #
class AudioSlicer:
    """Slices a demodulated PCM stream into bits at one bit phase.

    The FM-demodulated baseband is DC-blocked with a one-pole high-pass filter
    and sampled in the middle of each bit period. The bit phase of the
    transmitter cannot be known in advance, so :class:`PhasedSlicer` runs
    several instances of this class offset from each other.

    Args:
        sample_rate: audio sample rate in Hz (22050 is what rtl_fm gives).
        baud: bit rate - 512, 1200 or 2400.
        phase_samples: offset of this slicer's bit clock, in samples.
    """

    def __init__(self, sample_rate: int, baud: int, phase_samples: float = 0.0) -> None:
        """Create the slicer."""
        self.sample_rate = sample_rate
        self.baud = baud
        self.samples_per_bit = sample_rate / float(baud)
        self.dc_estimate = 0.0
        self.highpass = 0.995
        self.index = 0
        self.next_instant = phase_samples + self.samples_per_bit / 2.0
        self.bits = 0

    def push_sample(self, sample: float) -> Optional[int]:
        """Feed one audio sample.

        Args:
            sample: normalised sample (-1.0 .. 1.0).

        Returns:
            A bit when the sample instant falls inside a new bit period,
            otherwise ``None``.
        """
        # One-pole high-pass: removes the DC offset left by the FM discriminator
        self.dc_estimate = self.highpass * self.dc_estimate + (1 - self.highpass) * sample
        filtered = sample - self.dc_estimate
        self.index += 1
        if self.index < self.next_instant:
            return None
        self.next_instant += self.samples_per_bit
        self.bits += 1
        return 1 if filtered > 0.0 else 0


class PhasedSlicer:
    """Runs several bit phases in parallel and locks onto the one that syncs.

    While unsynchronised every phase is fed (that is the only way to find the
    transmitter's bit clock), which costs a few percent of a CPU core. As soon
    as one phase decodes a batch - or produces a message - the other phases are
    dropped and only the winning phase is processed.

    Args:
        sample_rate: audio sample rate in Hz.
        baud: bit rate.
        phases: how many bit-clock phases to try (default 4).
        logger: optional logger for lock/unlock messages.
    """

    def __init__(self, sample_rate: int, baud: int, phases: int = 4,
                 logger: Optional[Logger] = None) -> None:
        """Create the phased slicer."""
        self.phases = max(1, phases)
        self.logger = logger
        spacing = (sample_rate / float(baud)) / self.phases
        self.slicers = [AudioSlicer(sample_rate, baud, index * spacing)
                        for index in range(self.phases)]
        self.decoders = [PocsagBitDecoder() for _ in range(self.phases)]
        self.locked: Optional[int] = None
        self.lock_changes = 0

    def push_sample(self, sample: float) -> List[PagerMessage]:
        """Feed one audio sample to the active phases.

        Args:
            sample: normalised sample.

        Returns:
            Any messages completed by this sample.
        """
        completed: List[PagerMessage] = []
        if self.locked is None:
            for index in range(self.phases):
                completed.extend(self._feed(index, sample))
                if self.locked is not None:
                    break
            return completed

        completed.extend(self._feed(self.locked, sample))
        decoder = self.decoders[self.locked]
        if not decoder.in_sync and decoder.bad_batches >= 3:
            if self.logger is not None:
                self.logger.debug("lost bit phase %d - searching again", self.locked)
            self.locked = None
            self.decoders[decoder_index(self.decoders, decoder)] = PocsagBitDecoder()
        return completed

    def _feed(self, index: int, sample: float) -> List[PagerMessage]:
        """Feed one sample to one phase and handle locking.

        Args:
            index: phase index.
            sample: the sample.

        Returns:
            Any messages completed by this sample.
        """
        bit = self.slicers[index].push_sample(sample)
        if bit is None:
            return []
        messages = self.decoders[index].push_bit(bit)
        if self.locked == index:
            return messages
        if messages or (self.decoders[index].in_sync
                        and self.decoders[index].batch_count >= 2):
            self.locked = index
            self.lock_changes += 1
            if self.logger is not None:
                self.logger.debug("locked onto bit phase %d/%d", index + 1, self.phases)
        return messages

    def flush(self) -> List[PagerMessage]:
        """Flush every decoder at the end of a stream.

        Returns:
            Messages completed by the flush.
        """
        completed: List[PagerMessage] = []
        indices = [self.locked] if self.locked is not None else range(self.phases)
        for index in indices:
            completed.extend(self.decoders[index].flush_buffers("end of stream"))
        return completed

    @property
    def bit_count(self) -> int:
        """Total bits sliced by the winning (or busiest) phase."""
        if self.locked is not None:
            return self.decoders[self.locked].bit_count
        return sum(decoder.bit_count for decoder in self.decoders)

    @property
    def batch_count(self) -> int:
        """Total batches seen by the active decoders."""
        if self.locked is not None:
            return self.decoders[self.locked].batch_count
        return sum(decoder.batch_count for decoder in self.decoders)

    @property
    def codeword_errors(self) -> int:
        """Total corrected bit errors."""
        if self.locked is not None:
            return self.decoders[self.locked].codeword_errors
        return sum(decoder.codeword_errors for decoder in self.decoders)

    @property
    def messages(self) -> List[PagerMessage]:
        """Messages decoded by the active phase."""
        if self.locked is not None:
            return self.decoders[self.locked].messages
        return self.best_decoder().messages

    def best_decoder(self) -> PocsagBitDecoder:
        """Return the decoder that did the most work.

        While searching, several phases run at once; the statistics reported at
        the end of a run must come from the phase that actually decoded instead
        of from an empty one.

        Returns:
            The most productive decoder.
        """
        return max(self.decoders,
                   key=lambda decoder: (len(decoder.messages), decoder.bit_count))


def decoder_index(decoders: Sequence[PocsagBitDecoder],
                  target: PocsagBitDecoder) -> int:
    """Return the index of a decoder in a list.

    Args:
        decoders: the decoder list.
        target: the decoder to find.

    Returns:
        The index, or 0 when it is not found.
    """
    for index, decoder in enumerate(decoders):
        if decoder is target:
            return index
    return 0


class PagerDecoder:
    """Capture, slice and decode POCSAG traffic.

    Args:
        config: loaded cyberdeck configuration.
        logger: shared logger.
    """

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.install_dir = Path(str(config.get("general.install_dir",
                                               "/opt/cyberdeck-arsenal")))
        self.output_dir = self.install_dir / "captures" / "pager"
        self.frequency = int(float(config.get("sdr.pager_frequency", 153.35)) * 1e6) \
            if float(config.get("sdr.pager_frequency", 153.35)) < 1e6 \
            else int(config.get("sdr.pager_frequency", 153_350_000))
        self.sample_rate = int(config.get("sdr.pager_sample_rate", 22050))
        self.baud = int(config.get("sdr.pager_baud", 1200))
        self.gain = str(config.get("sdr.gain", "auto"))
        self.decoder = PocsagBitDecoder()
        # The slicer is created lazily so --baud/--sample-rate take effect
        self._slicer: Optional[PhasedSlicer] = None
        self.messages: List[PagerMessage] = []
        self.capcode_ranges: List[Tuple[int, int, str]] = []
        self.capcodes: Dict[int, str] = self.load_capcodes()
        self.running = True
        self.database: Optional[Database] = None
        try:
            self.database = Database("events")
        except Exception as exc:  # pragma: no cover
            self.logger.debug("events database unavailable: %s", exc)

    # -- capcode labels ---------------------------------------------------- #
    def load_capcodes(self) -> Dict[int, str]:
        """Load the capcode label map.

        Reads ``data/pager_capcodes.json`` (installed copy first, repository
        copy second) and separates exact capcodes from capcode ranges.

        Returns:
            A mapping of capcode to a human label (may be empty).
        """
        mapping: Dict[int, str] = {}
        ranges: List[Tuple[int, int, str]] = []
        candidates = [
            self.install_dir / "data" / "pager_capcodes.json",
            Path(__file__).resolve().parent.parent / "data" / "pager_capcodes.json",
        ]
        for path in candidates:
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                self.logger.warn("could not read %s: %s", path, exc)
                continue
            if not isinstance(data, dict):
                self.logger.warn("%s does not contain a JSON object - ignoring", path)
                continue
            for key, value in data.items():
                text = str(key).strip()
                if text.startswith("_"):
                    continue
                exact = re.fullmatch(r"(\d+)", text)
                span = re.fullmatch(r"(\d+)\s*-\s*(\d+)", text)
                if exact:
                    mapping[int(exact.group(1))] = str(value)
                elif span:
                    low, high = int(span.group(1)), int(span.group(2))
                    if low > high:
                        low, high = high, low
                    ranges.append((low, high, str(value)))
                else:
                    self.logger.debug("skipping capcode key %r", key)
            break
        self.capcode_ranges = ranges
        return mapping

    def label_for(self, capcode: int) -> str:
        """Return the label for a capcode.

        Keys of ``pager_capcodes.json`` may be an exact capcode
        (``"1234567": "Site-2 fire panel"``) or a range
        (``"2010000-2019999": "Ambulance pagers"``).

        Args:
            capcode: the pager capcode.

        Returns:
            The configured label, or an empty string when unknown.
        """
        if capcode in self.capcodes:
            return self.capcodes[capcode]
        for low, high, label in self.capcode_ranges:
            if low <= capcode <= high:
                return label
        return ""

    # -- slicer ------------------------------------------------------------ #
    @property
    def slicer(self) -> PhasedSlicer:
        """The bit slicer for the current baud rate (created on first use)."""
        if self._slicer is None:
            self._slicer = PhasedSlicer(self.sample_rate, self.baud, logger=self.logger)
        return self._slicer

    def reset_slicer(self) -> None:
        """Drop the slicer so the next capture uses the current baud rate."""
        self._slicer = None
        self.decoder = PocsagBitDecoder()

    # -- capture ----------------------------------------------------------- #
    def rtl_fm_command(self, duration: int) -> List[str]:
        """Build the rtl_fm command line for a pager capture.

        Args:
            duration: capture length in seconds.

        Returns:
            The command as an argument list.
        """
        return [
            "rtl_fm",
            "-f", str(self.frequency),
            "-M", "fm",
            "-s", str(self.sample_rate),
            "-g", self.gain,
            "-l", "0",
            "-A", "fast",
            "-p", "0",
            "-E", "",              # let rtl_fm stream until we close the pipe
            "-",
        ]

    def require_sdr(self) -> bool:
        """Check that rtl_fm and an SDR are available.

        Returns:
            True when a live capture is possible.
        """
        if shutil.which("rtl_fm") is None:
            self.logger.error("rtl_fm is not installed")
            self.logger.info("install it with: sudo pacman -S rtl-sdr")
            return False
        if not Hardware.sdr_devices():
            self.logger.error("no SDR device detected")
            self.logger.info("plug in the dongle, or replay a recording with --input FILE")
            return False
        return True

    def capture(self, duration: int, live: bool = False) -> int:
        """Capture and decode POCSAG traffic.

        Args:
            duration: capture seconds.
            live: render a live table as messages arrive.

        Returns:
            Process exit code.
        """
        command = self.rtl_fm_command(duration)
        self.logger.info("listening on %.4f MHz for %ss at %d baud",
                         self.frequency / 1e6, duration, self.baud)
        self.logger.debug("command: %s", " ".join(command))
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        except OSError as exc:
            self.logger.error("could not start rtl_fm: %s", exc)
            return 1
        self._install_signal_handlers()
        started = time.time()
        try:
            assert process.stdout is not None
            self.consume_stream(process.stdout, duration=duration, live=live)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    process.kill()
            if process.stderr is not None:
                error = process.stderr.read().decode(errors="replace").strip()
                if error and "error" in error.lower():
                    for line in error.splitlines()[:4]:
                        self.logger.warn("rtl_fm: %s", line)
        self.logger.ok("captured %ss, %d message(s)", int(time.time() - started),
                       len(self.messages))
        return 0

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers that stop the capture cleanly."""

        def stop(_signum: int, _frame: Any) -> None:
            self.running = False

        for name in ("SIGINT", "SIGTERM"):
            try:
                signal.signal(getattr(signal, name), stop)
            except (ValueError, OSError):  # pragma: no cover
                pass

    def consume_stream(self, stream: Any, duration: int = 0, live: bool = False,
                       chunk: int = 1 << 15) -> int:
        """Read a raw 16-bit little-endian PCM stream and decode it.

        Args:
            stream: a file-like object returning bytes.
            duration: stop after this many seconds (0 = until the stream ends).
            live: render a live table as messages arrive.
            chunk: read size in bytes.

        Returns:
            The number of messages decoded.
        """
        started = time.time()
        before = len(self.messages)
        self.reset_slicer()
        buffer = b""
        while self.running:
            if duration and time.time() - started > duration:
                break
            data = stream.read(chunk)
            if not data:
                break
            buffer += data
            usable = len(buffer) - (len(buffer) % 2)
            for index in range(0, usable, 2):
                sample = int.from_bytes(buffer[index:index + 2], "little", signed=True)
                for message in self.slicer.push_sample(sample / 32768.0):
                    self.handle_message(message, live=live)
            buffer = buffer[usable:]
        for message in self.slicer.flush():
            self.handle_message(message, live=live)
        self.decoder = self.slicer.best_decoder()
        return len(self.messages) - before

    def read_audio_file(self, path: Path, live: bool = False) -> int:
        """Decode a recorded raw PCM (s16le) file.

        Args:
            path: the recording.
            live: render a live table as messages arrive.

        Returns:
            Process exit code.
        """
        if not path.is_file():
            self.logger.error("no such audio file: %s", path)
            return 1
        self.logger.info("decoding %s (%.1f MB of PCM)", path, path.stat().st_size / 1e6)
        with path.open("rb") as handle:
            decoded = self.consume_stream(handle, duration=0, live=live)
        self.logger.ok("%d message(s) decoded", decoded)
        return 0

    def read_bit_file(self, path: Path) -> int:
        """Decode a text file of 0/1 bits.

        Args:
            path: the bit file.

        Returns:
            Process exit code.
        """
        if not path.is_file():
            self.logger.error("no such bit file: %s", path)
            return 1
        text = path.read_text(errors="replace")
        digits = [character for character in text if character in "01"]
        if len(digits) < 64:
            self.logger.error("the file contains too few bits to decode (%d)", len(digits))
            return 1
        for character in digits:
            for message in self.decoder.push_bit(int(character)):
                self.handle_message(message)
        for message in self.decoder.flush_buffers("end of bits"):
            self.handle_message(message)
        self.logger.ok("%d bit(s) → %d message(s)", len(digits), len(self.messages))
        return 0

    # -- message handling -------------------------------------------------- #
    def handle_message(self, message: PagerMessage, live: bool = False) -> None:
        """Record a decoded message and report it.

        Args:
            message: the decoded message.
            live: redraw the live table when True.
        """
        message.frequency_hz = self.frequency
        message.baud = self.baud
        message.label = self.label_for(message.capcode)
        if looks_like_garbage(message.text):
            self.logger.debug("discarding likely noise for capcode %s: %r",
                              message.capcode, message.text)
            return
        self.messages.append(message)
        self.logger.ok("%s", message.display)
        if self.database is not None:
            try:
                self.database.event("pager_decoder", "pager", message.display, "INFO",
                                    data=message.as_dict())
            except Exception as exc:  # pragma: no cover
                self.logger.debug("event insert failed: %s", exc)
        if live:
            self.render_live()

    def render_live(self, limit: int = 18) -> None:
        """Render recent messages (Rich when available).

        Args:
            limit: how many messages to show.
        """
        recent = self.messages[-limit:]
        try:
            from rich.console import Console
            from rich.table import Table
        except ImportError:
            self.render_plain_table(recent)
            return
        console = Console()
        table = Table(title=f"POCSAG · {self.frequency / 1e6:.4f} MHz · "
                            f"{self.baud} baud · {len(self.messages)} message(s)",
                      header_style="bold cyan")
        for column in ("TIME", "CAPCODE", "LABEL", "MODE", "TEXT", "ERR"):
            table.add_column(column)
        for message in recent:
            table.add_row(message.received[11:19], str(message.capcode),
                          message.label or "—", message.mode,
                          message.text[:60], str(message.bit_errors))
        console.clear()
        console.print(table)

    def render_plain_table(self, rows: Optional[Sequence[PagerMessage]] = None) -> None:
        """Render messages as plain text.

        Args:
            rows: messages to show (defaults to the last 25).
        """
        rows = rows if rows is not None else self.messages[-25:]
        print()
        print(f"  {'TIME':<10}{'CAPCODE':>10}  {'MODE':<14}{'ERR':>4}  TEXT")
        print("  " + "─" * 84)
        for message in rows:
            print(f"  {message.received[11:19]:<10}{message.capcode:>10}  "
                  f"{message.mode:<14}{message.bit_errors:>4}  {message.text[:48]}")
        print()

    def summary(self) -> Dict[str, Any]:
        """Build the session summary.

        Returns:
            Counters, per-capcode totals and the message list.
        """
        per_capcode: Dict[str, int] = defaultdict(int)
        for message in self.messages:
            per_capcode[str(message.capcode)] += 1
        best = self.slicer.best_decoder() if self._slicer is not None else self.decoder
        return {
            "version": VERSION,
            "generated": now_iso(),
            "frequency_hz": self.frequency,
            "baud": self.baud,
            "sample_rate": self.sample_rate,
            "bit_phase": self._slicer.locked if self._slicer is not None else 0,
            "bits_processed": best.bit_count,
            "batches": best.batch_count,
            "corrected_bit_errors": best.codeword_errors,
            "messages": len(self.messages),
            "capcodes": dict(sorted(per_capcode.items(),
                                    key=lambda item: -item[1])),
            "decoded": [message.as_dict() for message in self.messages],
        }

    def write_outputs(self, label: Optional[str] = None) -> Dict[str, Path]:
        """Write the JSONL, CSV and summary artefacts.

        Args:
            label: optional name for the run.

        Returns:
            A mapping of artefact name to path.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = label or datetime.now().strftime("%Y%m%d_%H%M%S")
        artefacts: Dict[str, Path] = {}

        jsonl = self.output_dir / f"messages_{stamp}.jsonl"
        with jsonl.open("w") as handle:
            for message in self.messages:
                handle.write(json.dumps(message.as_dict()) + "\n")
        artefacts["jsonl"] = jsonl

        csv_path = self.output_dir / f"messages_{stamp}.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["received", "capcode", "label", "function", "mode", "text",
                             "bit_errors", "codewords", "frequency_hz", "baud"])
            for message in self.messages:
                writer.writerow([message.received, message.capcode, message.label,
                                 message.function, message.mode, message.text,
                                 message.bit_errors, message.codewords,
                                 message.frequency_hz, message.baud])
        artefacts["csv"] = csv_path

        summary_file = self.output_dir / f"summary_{stamp}.json"
        summary_file.write_text(json.dumps(summary_data, indent=2) + "\n")
        artefacts["json"] = summary_file

        # Human-readable copy for pasting into a report appendix
        text = self.output_dir / f"messages_{stamp}.md"
        lines = [f"# POCSAG log - {stamp}", "",
                 f"- frequency: {self.frequency / 1e6:.4f} MHz",
                 f"- baud: {self.baud}",
                 f"- messages: {len(self.messages)}",
                 f"- batches decoded: {summary_data['batches']}",
                 f"- corrected bit errors: {summary_data['corrected_bit_errors']}", "",
                 "| received | capcode | mode | text |", "| --- | --- | --- | --- |"]
        for message in self.messages:
            safe = message.text.replace("|", "\\|")
            lines.append(f"| {message.received} | {message.capcode} "
                         f"{('(' + message.label + ')') if message.label else ''} | "
                         f"{message.mode} | {safe} |")
        text.write_text("\n".join(lines) + "\n")
        artefacts["markdown"] = text

        self.logger.ok("artefacts written to %s", self.output_dir)
        return artefacts

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
        prog="pager_decoder.py",
        description="POCSAG pager decoder with BCH error correction (receive only)",
        epilog="paging traffic can contain personal data - handle captures accordingly")
    parser.add_argument("--version", action="version", version=f"pager_decoder {VERSION}")
    parser.add_argument("--frequency", "-f", type=float, default=None,
                        help="centre frequency in MHz (default: from cyberdeck.conf)")
    parser.add_argument("--duration", type=int, default=120,
                        help="capture seconds (default: 120)")
    parser.add_argument("--baud", type=int, default=None, choices=[512, 1200, 2400],
                        help="bit rate (default: from cyberdeck.conf, usually 1200)")
    parser.add_argument("--input", type=Path, default=None,
                        help="decode a recorded raw PCM (s16le) file")
    parser.add_argument("--bits", type=Path, default=None,
                        help="decode a text file containing 0/1 bits")
    parser.add_argument("--gain", default=None, help="tuner gain (dB or 'auto')")
    parser.add_argument("--live", action="store_true", help="redraw the table as messages arrive")
    parser.add_argument("--write", action="store_true",
                        help="write JSONL/CSV/Markdown artefacts under captures/pager/")
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the POCSAG decoder.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 success, 1 failure, 3 no SDR.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("pager_decoder", level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("POCSAG pager decoder", f"v{VERSION} · 512/1200/2400 baud")

    decoder = PagerDecoder(config, logger)
    if args.frequency:
        decoder.frequency = int(args.frequency * 1e6)
    if args.baud:
        decoder.baud = args.baud
    if args.gain:
        decoder.gain = args.gain

    try:
        if args.bits is not None:
            code = decoder.read_bit_file(args.bits)
        elif args.input is not None:
            code = decoder.read_audio_file(args.input, live=args.live)
        else:
            if not decoder.require_sdr():
                logger.info("offline mode: ./pager_decoder.py --input recording.raw")
                return 3
            code = decoder.capture(args.duration, live=args.live)

        if code == 0:
            if args.write and decoder.messages:
                decoder.write_outputs()
            if args.json:
                print(json.dumps(decoder.summary(), indent=2))
            else:
                decoder.render_plain_table()
                summary = decoder.summary()
                logger.info("capcodes seen: %s", ", ".join(summary["capcodes"]) or "none")
                logger.info("corrected %d bit error(s) across %d batch(es)",
                            summary["corrected_bit_errors"], summary["batches"])
        return code
    finally:
        decoder.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
