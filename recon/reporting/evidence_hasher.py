#!/usr/bin/env python3
"""
evidence_hasher.py - chain-of-custody hashing for cyberdeck-arsenal
===================================================================

Description
-----------
Hashes captured artefacts (network captures, images, payloads, logs, downloads)
with MD5, SHA-1 and SHA-256, records them in an append-only chain-of-custody log
with timestamps, operator identity and file metadata, and verifies integrity on
demand.

The log is append-only by design: each entry includes the hash of the previous
entry, so tampering with any historical record is detectable. Verification
re-computes every hash and checks the chain.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; stdlib only (hashlib, json, os)
Licence     : MIT - evidence handling must comply with your engagement contract
              and local law (see docs/LEGAL.md)

Usage
-----
    cdeck hash captures/                  # hash every file in a directory
    cdeck hash evidence.zip --note "handover to client"
    cdeck hash --verify                   # re-verify every recorded artefact
    cdeck hash --log                      # show the custody log
    python3 recon/reporting/evidence_hasher.py file.bin --json
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import socket
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent.parent / "lib",
    Path(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")) / "lib",
]
for _candidate in _LIB_CANDIDATES:
    if (_candidate / "cyberlib.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

try:
    from cyberlib import (  # type: ignore
        C, Config, Logger, colour, human_bytes, now_iso, write_json,
    )
except ImportError as exc:
    print(f"evidence_hasher: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

CHUNK_SIZE = 1024 * 1024  # 1 MiB read size: memory-safe on huge images


@dataclass
class HashResult:
    """Hashes and metadata for one artefact."""

    path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    modified: str
    mode: str
    hashed_at: str = field(default_factory=now_iso)
    note: str = ""
    operator: str = ""
    host: str = ""
    file_type: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """Serialise the record."""
        return {
            "path": self.path, "size": self.size, "md5": self.md5, "sha1": self.sha1,
            "sha256": self.sha256, "modified": self.modified, "mode": self.mode,
            "hashed_at": self.hashed_at, "note": self.note, "operator": self.operator,
            "host": self.host, "file_type": self.file_type,
        }

    def as_line(self) -> str:
        """Return the classic ``sha256  path`` line used by sha256sum -c."""
        return f"{self.sha256}  {self.path}"


class EvidenceHasher:
    """Hashes artefacts and maintains a tamper-evident custody log."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None,
                 log_path: Optional[Path] = None) -> None:
        """Prepare the hasher and its log location."""
        self.config = config or Config().load()
        self.logger = logger or Logger("evidence_hasher",
                                       str(self.config.get("general.log_level", "INFO")))
        install = Path(self.config.get("general.install_dir", "/opt/cyberdeck-arsenal"))
        self.log_path = Path(log_path) if log_path else install / "data" / "chain_of_custody.jsonl"
        self.entries: List[Dict[str, Any]] = []
        self._load_log()

    # -- log handling ------------------------------------------------------- #
    def _load_log(self) -> None:
        """Read the existing log (JSON lines)."""
        if not self.log_path.exists():
            return
        try:
            for line in self.log_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self.entries.append(json.loads(line))
                except json.JSONDecodeError:
                    self.logger.warn(f"skipping malformed custody line: {line[:60]}")
        except OSError as exc:
            self.logger.error(f"could not read the custody log: {exc}")

    def _append(self, record: Dict[str, Any]) -> None:
        """Append a record, chaining it to the previous entry's hash."""
        previous_hash = self.entries[-1]["entry_hash"] if self.entries else "0" * 64
        record["previous_entry_hash"] = previous_hash
        record["sequence"] = len(self.entries) + 1
        canonical = json.dumps({key: value for key, value in record.items()
                                if key != "entry_hash"}, sort_keys=True)
        record["entry_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        self.log_path = self._ensure_writable(self.log_path)
        with open(self.log_path, "a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.entries.append(record)

    def _ensure_writable(self, path: Path) -> Path:
        """Return *path* if it can be created, else a per-user fallback.

        The custody log normally lives in ``<install>/data``, which a
        non-privileged operator cannot create. Rather than failing the whole
        run, fall back to ``~/.cyberdeck-arsenal`` and say so.

        Args:
            path: the preferred custody-log location.

        Returns:
            A path whose parent directory exists and is writable.
        """
        candidates = [path, Path.home() / ".cyberdeck-arsenal" / path.name]
        for candidate in candidates:
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                if candidate.exists() and not candidate.is_file():
                    continue
                return candidate
            except (PermissionError, OSError):
                continue
        # Last resort: next to the artefacts being hashed
        fallback = Path.cwd() / path.name
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback

    # -- hashing ------------------------------------------------------------ #
    @staticmethod
    def hash_file(path: Path) -> Tuple[str, str, str]:
        """Return ``(md5, sha1, sha256)`` for a file, streaming it in chunks."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

    @staticmethod
    def _file_type(path: Path) -> str:
        """Best-effort file type description (no libmagic dependency)."""
        try:
            with open(path, "rb") as handle:
                header = handle.read(16)
        except OSError:
            return "unreadable"
        signatures = {
            b"\x89PNG": "PNG image", b"\xff\xd8\xff": "JPEG image", b"GIF8": "GIF image",
            b"PK\x03\x04": "ZIP archive", b"\x1f\x8b": "gzip archive",
            b"\x7fELF": "ELF binary", b"RIFF": "RIFF container",
            b"%PDF": "PDF document", b"\xd4\xc3\xb2\xa1": "pcap capture",
            b"\x0a\x0d\x0d\x0a": "pcapng capture", b"SQLite format 3": "SQLite database",
        }
        for signature, description in signatures.items():
            if header.startswith(signature):
                return description
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            return "pcapng capture"
        try:
            header.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            return "binary"

    def record(self, path: Path, note: str = "", recursive: bool = False) -> List[HashResult]:
        """Hash *path* (file or directory) and append every result to the log."""
        path = Path(path)
        results: List[HashResult] = []
        if not path.exists():
            self.logger.error(f"path does not exist: {path}")
            return results

        targets: Iterator[Path]
        if path.is_dir():
            if not recursive and not any(path.iterdir()):
                self.logger.warn(f"directory is empty: {path}")
                return results
            targets = (item for item in sorted(path.rglob("*")) if item.is_file())
            self.logger.info(f"hashing every file under {path} "
                             f"({'recursive' if recursive else 'tree walk'})")
        else:
            targets = iter([path])

        for target in targets:
            try:
                file_stat = target.stat()
            except OSError as exc:
                self.logger.warn(f"cannot stat {target}: {exc}")
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                self.logger.debug(f"skipping non-regular file: {target}")
                continue
            try:
                md5, sha1, sha256 = self.hash_file(target)
            except (OSError, PermissionError) as exc:
                self.logger.error(f"could not hash {target}: {exc}")
                continue
            result = HashResult(
                path=str(target), size=file_stat.st_size, md5=md5, sha1=sha1, sha256=sha256,
                modified=datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                mode=oct(file_stat.st_mode & 0o7777),
                note=note,
                operator=getpass.getuser() if hasattr(getpass, "getuser") else os.environ.get("USER", "unknown"),
                host=socket.gethostname(),
                file_type=self._file_type(target))
            self._append(result.as_dict())
            results.append(result)
            self.logger.ok(f"{sha256[:16]}… {human_bytes(result.size):>9}  {target}")
        return results

    # -- verification ------------------------------------------------------- #
    def verify(self, path: Optional[Path] = None, verify_chain: bool = True,
               deep: bool = True) -> Dict[str, Any]:
        """Verify recorded artefacts against the on-disk files.

        Steps:
            1. every entry hash and previous-entry link is recomputed
            2. every recorded path is re-hashed and compared (unless deep=False)
            3. missing files are reported separately from modified files
        """
        report: Dict[str, Any] = {
            "log": str(self.log_path),
            "entries": len(self.entries),
            "chain_ok": True,
            "chain_problems": [],
            "verified": [],
            "modified": [],
            "missing": [],
            "unreadable": [],
        }

        if verify_chain:
            previous = "0" * 64
            for index, entry in enumerate(self.entries):
                stored_hash = entry.get("entry_hash")
                replay = {key: value for key, value in entry.items() if key != "entry_hash"}
                canonical = json.dumps(replay, sort_keys=True)
                recomputed = hashlib.sha256(canonical.encode()).hexdigest()
                if recomputed != stored_hash:
                    report["chain_ok"] = False
                    report["chain_problems"].append(
                        f"entry {index + 1} hash mismatch (log may have been edited)")
                if entry.get("previous_entry_hash") != previous:
                    report["chain_ok"] = False
                    report["chain_problems"].append(
                        f"entry {index + 1} is not linked to the previous entry "
                        f"(possible insertion or deletion)")
                previous = stored_hash or ""

        targets = self.entries
        if path:
            resolved = str(Path(path).expanduser())
            targets = [entry for entry in self.entries
                       if entry.get("path", "").startswith(resolved)]

        for entry in targets:
            recorded_path = Path(entry.get("path", ""))
            if not recorded_path.exists():
                report["missing"].append(str(recorded_path))
                continue
            if not deep:
                continue
            try:
                _, _, sha256 = self.hash_file(recorded_path)
            except OSError as exc:
                report["unreadable"].append(f"{recorded_path}: {exc}")
                continue
            if sha256 == entry.get("sha256"):
                report["verified"].append(str(recorded_path))
            else:
                report["modified"].append({
                    "path": str(recorded_path),
                    "expected": entry.get("sha256"),
                    "actual": sha256,
                })
        return report

    def render_verification(self, report: Dict[str, Any]) -> str:
        """Render a verification report as colourised text."""
        lines = [
            colour(f"  EVIDENCE VERIFICATION  ::  {now_iso()}", C.BRIGHT_CYAN),
            f"  log file : {report['log']}",
            f"  entries  : {report['entries']}",
            f"  chain    : {colour('intact', C.BRIGHT_GREEN) if report['chain_ok'] else colour('BROKEN', C.BRIGHT_RED)}",
            "",
            colour(f"  verified : {len(report['verified'])}", C.GREEN),
            colour(f"  modified : {len(report['modified'])}",
                   C.BRIGHT_RED if report["modified"] else C.DIM),
            colour(f"  missing  : {len(report['missing'])}",
                   C.BRIGHT_YELLOW if report["missing"] else C.DIM),
            colour(f"  unreadable: {len(report['unreadable'])}", C.DIM),
        ]
        for problem in report["chain_problems"]:
            lines.append(colour(f"  ! {problem}", C.BRIGHT_RED))
        for item in report["modified"]:
            lines.append(colour(f"  ✘ MODIFIED {item['path']}", C.BRIGHT_RED))
            lines.append(colour(f"      expected {item['expected']}", C.DIM))
            lines.append(colour(f"      actual   {item['actual']}", C.DIM))
        for item in report["missing"]:
            lines.append(colour(f"  ! MISSING {item}", C.YELLOW))
        for item in report["unreadable"]:
            lines.append(colour(f"  ! UNREADABLE {item}", C.YELLOW))
        return "\n".join(lines)

    # -- reporting ---------------------------------------------------------- #
    def render_log(self, limit: int = 40) -> str:
        """Render the custody log as text."""
        lines = [
            colour(f"  CHAIN OF CUSTODY  ::  {self.log_path}", C.BRIGHT_CYAN),
            colour(f"  {len(self.entries)} entr(ies)", C.DIM),
            "",
            f"  {'#':<5}{'WHEN':<21}{'SIZE':>10}  {'SHA-256':<18}  PATH",
        ]
        for entry in self.entries[-limit:]:
            lines.append(
                f"  {entry.get('sequence', '?'):<5}"
                f"{entry.get('hashed_at', '')[:19]:<21}"
                f"{human_bytes(entry.get('size', 0)):>10}  "
                f"{(entry.get('sha256', '')[:16] or '-'):<18}  {entry.get('path', '')}")
            if entry.get("note"):
                lines.append(colour(f"        note: {entry['note']}", C.DIM))
        if not self.entries:
            lines.append("  log is empty - hash something with: cdeck hash <dir>")
        return "\n".join(lines)

    def export(self, path: Path, format_name: str = "json") -> Path:
        """Export the log as JSON, CSV or a sha256sum manifest."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if format_name == "json":
            return write_json(path, self.entries)
        if format_name == "csv":
            columns = list(self.entries[0].keys()) if self.entries else ["path", "sha256"]
            with open(path, "w") as handle:
                handle.write(",".join(columns) + "\n")
                for entry in self.entries:
                    handle.write(",".join(
                        f'"{str(entry.get(column, "")).replace(chr(34), chr(39))}"'
                        for column in columns) + "\n")
            return path
        # sha256sum-compatible manifest
        path.write_text("\n".join(f"{entry.get('sha256')}  {entry.get('path')}"
                                  for entry in self.entries) + "\n")
        return path

    def verify_manifest(self, manifest: Path) -> Tuple[int, int, int]:
        """Verify against an external ``sha256sum`` manifest.

        Returns ``(ok, mismatched, missing)``.
        """
        ok = mismatched = missing = 0
        for line in Path(manifest).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            expected, raw_path = parts[0], parts[1].strip()
            target = Path(raw_path.lstrip("*"))
            if not target.exists():
                missing += 1
                continue
            try:
                _, _, actual = self.hash_file(target)
            except OSError:
                missing += 1
                continue
            if actual == expected:
                ok += 1
            else:
                mismatched += 1
                self.logger.error(f"mismatch: {target}")
        return ok, mismatched, missing


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="evidence_hasher.py",
        description="chain-of-custody hashing (MD5/SHA1/SHA256) with tamper-evident log",
        epilog="Also available as: cdeck hash <dir>")
    parser.add_argument("paths", nargs="*", help="files or directories to hash")
    parser.add_argument("--note", default="", help="note to record with this batch")
    parser.add_argument("--recursive", action="store_true", help="recurse into subdirectories")
    parser.add_argument("--verify", action="store_true",
                        help="verify recorded artefacts against the files on disk")
    parser.add_argument("--verify-only", metavar="PATH", default=None,
                        help="verify only entries under PATH")
    parser.add_argument("--no-chain-check", action="store_true",
                        help="skip the log integrity (hash chain) check")
    parser.add_argument("--shallow", action="store_true",
                        help="during verification, only check that files exist (no re-hash)")
    parser.add_argument("--manifest", metavar="FILE", default=None,
                        help="verify against an external sha256sum manifest")
    parser.add_argument("--log", action="store_true", help="print the custody log")
    parser.add_argument("--export", metavar="FILE", default=None, help="export the log to FILE")
    parser.add_argument("--export-format", choices=["json", "csv", "manifest"], default="json",
                        help="format for --export")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--log-path", default=None, help="use an alternative custody log")
    parser.add_argument("--version", action="version", version=f"evidence_hasher {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("evidence_hasher", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)))
    hasher = EvidenceHasher(config, logger,
                           Path(args.log_path).expanduser() if args.log_path else None)

    exit_code = 0

    # -- verification -------------------------------------------------------- #
    if args.verify or args.verify_only:
        target = Path(args.verify_only).expanduser() if args.verify_only else None
        report = hasher.verify(path=target, verify_chain=not args.no_chain_check,
                               deep=not args.shallow)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(hasher.render_verification(report))
        if report["modified"] or report["missing"] or not report["chain_ok"]:
            logger.alert("verification found discrepancies - investigate before relying on "
                         "this evidence")
            exit_code = 1
        else:
            logger.ok(f"{len(report['verified'])} artefact(s) verified intact")
        return exit_code

    # -- external manifest --------------------------------------------------- #
    if args.manifest:
        ok, mismatched, missing = hasher.verify_manifest(Path(args.manifest))
        print(f"  manifest : {args.manifest}")
        print(f"  ok       : {ok}")
        print(f"  mismatch : {mismatched}")
        print(f"  missing  : {missing}")
        return 1 if (mismatched or missing) else 0

    # -- hashing ------------------------------------------------------------- #
    if args.paths:
        total = 0
        for raw_path in args.paths:
            hashed = hasher.record(Path(raw_path).expanduser(), note=args.note,
                                   recursive=args.recursive)
            total += len(hashed)
        if args.json:
            # Emit the log entries written by this run, verbatim
            print(json.dumps(hasher.entries[-total:] if total else [], indent=2))
        else:
            logger.banner("evidence hashing complete",
                          f"{total} file(s) recorded in {hasher.log_path}")

    if args.log:
        print(hasher.render_log())

    if args.export:
        path = hasher.export(Path(args.export).expanduser(), args.export_format)
        logger.ok(f"custody log exported to {path}")

    if not (args.paths or args.log or args.export):
        print(hasher.render_log())
        print()
        print(colour("  usage: cdeck hash <file-or-directory> [--note 'handover to client']",
                     C.DIM))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
