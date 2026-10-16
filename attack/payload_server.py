#!/usr/bin/env python3
"""
attack/payload_server.py - authorised payload delivery and evidence collector.
==============================================================================

Description
-----------
A small, auditable HTTP server for the delivery phase of an authorised
social-engineering or red-team engagement. It does three jobs and records
everything it does:

**Delivery** - serves the files staged in ``<install>/payloads`` with correct
MIME types, HTTP range support (so a large installer resumes), directory
listing, per-file SHA-256 and a landing page that renders the delivery templates
in ``data/templates/`` with the engagement variables filled in.

**Collection** - ``POST /upload`` accepts files pushed by a client (an exfil
stager, a scripted beacon or an operator uploading evidence), ``GET /callback``
returns a 1x1 GIF and ``GET /ping`` returns 204; both record the client address,
user agent and query string.

**Evidence** - every request is appended to
``captures/payload/<stamp>/requests.jsonl`` and to the shared events database,
uploads are stored under the same directory and hashed with SHA-256 at rest,
and the session finishes with ``SUMMARY.md`` plus an optional chain-of-custody
seal through ``recon/reporting/evidence_hasher.py``.

Safety rails that are always on: request/upload size limits, a deny-list of
paths, no directory traversal (raw and percent-encoded), optional basic auth,
optional read-only mode, and a legal confirmation before the socket is bound.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: Python standard library only (optional: openssl for --tls)
Licence     : MIT - authorised use only (see docs/LEGAL.md)

Usage
-----
    sudo ./payload_server.py --port 8080 --duration 3600
    ./payload_server.py --list                       # what is staged
    ./payload_server.py --check                      # validate the staging dir
    ./payload_server.py --tls --port 8443            # self-signed HTTPS
"""

from __future__ import annotations

import argparse
import base64
import csv
import email.utils
import hashlib
import http.server
import json
import mimetypes
import os
import posixpath
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
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
        Logger,
        colour,
        confirm,
        human_bytes,
        now_iso,
        require_acknowledgement,
    )
except ImportError as exc:  # pragma: no cover - broken install
    sys.stderr.write(f"fatal: cyberlib.py is not importable ({exc})\n")
    sys.exit(1)

VERSION = "1.0.0"

#: Never serve these, even if a copy ends up in the staging directory
DENY_NAMES = {
    ".git", ".gitignore", ".env", "id_rsa", "id_ed25519", "known_hosts",
    "cyberdeck.conf", "auth.json", "credentials.json", "shadow", "passwd",
}
DENY_SUFFIXES = {".conf", ".pem", ".key", ".p12", ".pfx", ".kdbx", ".ovpn"}

#: A 1x1 transparent GIF, returned by /callback
PIXEL_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

#: Delivery templates written into the staging directory on first run
DELIVERY_TEMPLATES: Dict[str, str] = {
    "invoice.html": """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Invoice ready for review</title>
<style>
 body {{ background:#0b0f14; color:#c7f9ff; font-family: "DejaVu Sans Mono", monospace;
        margin:0; padding:3rem; }}
 .card {{ max-width:46rem; margin:auto; border:1px solid #1f6f78; border-radius:12px;
          padding:2rem; background:#0f1720; box-shadow:0 0 24px #062a2f inset; }}
 h1 {{ color:#39ff14; font-size:1.3rem; letter-spacing:.08em; }}
 a.button {{ display:inline-block; margin-top:1.2rem; padding:.7rem 1.2rem; border-radius:8px;
             background:#39ff14; color:#04140a; text-decoration:none; font-weight:bold; }}
 small {{ color:#5f8f96; }}
</style></head>
<body><div class="card">
 <h1>Invoice {engagement}</h1>
 <p>An invoice has been published to your account and requires review before
    {deadline}.</p>
 <p><a class="button" href="/{payload}">Open the invoice</a></p>
 <p><small>Reference {reference} · delivered {generated}</small></p>
</div></body></html>
""",
    "update.html": """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Mandatory update</title>
<style>
 body {{ background:#101014; color:#e8e8ef; font-family: system-ui, sans-serif;
        margin:0; padding:3rem; }}
 .card {{ max-width:40rem; margin:auto; border-radius:14px; padding:2rem;
          background:#1a1a22; border:1px solid #3a3a4a; }}
 a.button {{ display:inline-block; margin-top:1rem; padding:.7rem 1.2rem; border-radius:8px;
             background:#4f8cff; color:#04101f; text-decoration:none; font-weight:600; }}
 code {{ background:#26262f; padding:.15rem .4rem; border-radius:4px; }}
</style></head>
<body><div class="card">
 <h2>Update required</h2>
 <p>Your client ({engagement}) must be updated to continue. Download the package
    below, then run <code>{command}</code>.</p>
 <p><a class="button" href="/{payload}">Download the update</a></p>
 <p><small>{reference} · {generated}</small></p>
</div></body></html>
""",
}


@dataclass
class RequestRecord:
    """One HTTP request seen by the server."""

    timestamp: str
    client: str
    method: str
    path: str
    status: int
    bytes_sent: int = 0
    user_agent: str = ""
    referer: str = ""
    query: str = ""
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """Return the record as a plain dictionary."""
        return {
            "timestamp": self.timestamp,
            "client": self.client,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "bytes": self.bytes_sent,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "query": self.query,
            "note": self.note,
        }


@dataclass
class ServerState:
    """Mutable state shared between the handler threads and the console."""

    started: str = field(default_factory=now_iso)
    requests: List[RequestRecord] = field(default_factory=list)
    uploads: List[Dict[str, Any]] = field(default_factory=list)
    callbacks: List[Dict[str, Any]] = field(default_factory=list)
    cli_count: Dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    logfile: Optional[Path] = None
    upload_dir: Optional[Path] = None
    payload_dir: Optional[Path] = None
    templates: Dict[str, str] = field(default_factory=dict)
    variables: Dict[str, str] = field(default_factory=dict)
    max_upload_bytes: int = 64 * 1024 * 1024
    read_only: bool = False
    auth: Optional[Tuple[str, str]] = None
    database: Optional[Database] = None
    logger: Optional[Logger] = None
    hash_uploads: bool = True

    # -- summary ----------------------------------------------------------- #
    def summary(self) -> Dict[str, Any]:
        """Build the session summary (also returned by ``GET /status``).

        Returns:
            Counters, per-client totals and the ingest lists.
        """
        state = self
        per_client: Dict[str, int] = {}
        per_path: Dict[str, int] = {}
        for record in state.requests:
            per_client[record.client] = per_client.get(record.client, 0) + 1
            per_path[record.path] = per_path.get(record.path, 0) + 1
        return {
            "version": VERSION,
            "started": state.started,
            "uptime_s": int((datetime.fromisoformat(now_iso())
                             - datetime.fromisoformat(state.started)).total_seconds()),
            "requests": len(state.requests),
            "bytes_served": state.total_bytes(),
            "unique_clients": len(per_client),
            "clients": per_client,
            "paths": per_path,
            "uploads": state.uploads,
            "callbacks": state.callbacks,
            "counters": state.cli_count,
            "payload_dir": str(state.payload_dir) if state.payload_dir else "",
            "read_only": state.read_only,
        }


    def total_bytes(self) -> int:
        """Total bytes served in this session."""
        return sum(record.bytes_sent for record in self.requests)

    def counter(self, key: str) -> int:
        """Return and increment a named counter.

        Args:
            key: counter name.

        Returns:
            The value after incrementing.
        """
        with self.lock:
            self.cli_count[key] = self.cli_count.get(key, 0) + 1
            return self.cli_count[key]


def safe_join(root: Path, url_path: str) -> Optional[Path]:
    """Resolve a URL path inside a root directory, refusing traversal.

    Args:
        root: the directory that must contain the result.
        url_path: the (already decoded) URL path.

    Returns:
        The resolved path, or ``None`` when the path escapes the root or hits a
        deny-listed name.
    """
    decoded = urllib.parse.unquote(url_path)
    decoded = decoded.replace("\\", "/")
    cleaned = posixpath.normpath("/" + decoded.replace("//", "/"))
    relative = cleaned.lstrip("/")
    if relative in ("", "."):
        return root
    parts = [part for part in relative.split("/") if part not in ("", ".")]
    for part in parts:
        if part in DENY_NAMES or part.startswith("."):
            return None
        for suffix in DENY_SUFFIXES:
            if part.lower().endswith(suffix):
                return None
    candidate = (root / Path(*parts)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def sha256_of(path: Path) -> str:
    """Return the SHA-256 of a file.

    Args:
        path: the file.

    Returns:
        The hexadecimal digest, or an empty string on error.
    """
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return ""
    return digest.hexdigest()


def list_payloads(root: Path) -> List[Dict[str, Any]]:
    """List the staged payloads.

    Args:
        root: the staging directory.

    Returns:
        One dictionary per file, sorted by name.
    """
    entries: List[Dict[str, Any]] = []
    if not root.is_dir():
        return entries
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if safe_join(root, "/" + str(path.relative_to(root))) is None:
            continue
        stat = path.stat()
        entries.append({
            "name": str(path.relative_to(root)),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "sha256": sha256_of(path) if stat.st_size <= 128 * 1024 * 1024 else "skipped",
        })
    return entries


class PayloadHandler(http.server.BaseHTTPRequestHandler):
    """Request handler implementing the delivery and collection endpoints."""

    server_version = f"cyberdeck-payload/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    #: Populated by :func:`serve`
    state: ServerState

    # -- helpers ----------------------------------------------------------- #
    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence the default stderr logging; everything goes to the recorder."""
        del fmt, args

    def client_ip(self) -> str:
        """Return the client address, honouring a single proxy header.

        Returns:
            The best guess at the real client address.
        """
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "unknown"

    def record(self, status: int, note: str = "", bytes_sent: int = 0) -> None:
        """Record a request in memory, in the JSONL log and in the database.

        Args:
            status: HTTP status code returned.
            note: free-text note (endpoint name, refusal reason).
            bytes_sent: response body size.
        """
        record = RequestRecord(
            timestamp=now_iso(),
            client=self.client_ip(),
            method=self.command,
            path=self.path,
            status=status,
            bytes_sent=bytes_sent,
            user_agent=self.headers.get("User-Agent", ""),
            referer=self.headers.get("Referer", ""),
            query=urllib.parse.urlparse(self.path).query,
            note=note,
        )
        state = self.state
        with state.lock:
            state.requests.append(record)
            if state.logfile is not None:
                try:
                    with state.logfile.open("a") as handle:
                        handle.write(json.dumps(record.as_dict()) + "\n")
                except OSError:
                    pass
        if state.database is not None and note in ("upload", "callback", "denied"):
            try:
                severity = "WARNING" if note == "denied" else "INFO"
                state.database.event("payload_server", "payload",
                                     f"{note}: {record.method} {record.path} "
                                     f"from {record.client}", severity,
                                     data=record.as_dict())
            except Exception:  # pragma: no cover
                pass
        if state.logger is not None and note:
            state.logger.info("%s %s %s → %d (%s)", record.client, record.method,
                              record.path, status, note)

    def authorised(self) -> bool:
        """Check the optional basic-auth credentials.

        Returns:
            True when no credentials are configured or they match.
        """
        state = self.state
        if state.auth is None:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8", "replace")
        except Exception:
            return False
        user, _, password = decoded.partition(":")
        return (user, password) == state.auth

    def require_auth(self) -> bool:
        """Send a 401 when credentials are required and missing.

        Returns:
            True when the request may continue.
        """
        if self.authorised():
            return True
        self.respond(HTTPStatus.UNAUTHORIZED, b"authentication required\n",
                     content_type="text/plain", extra={"WWW-Authenticate":
                                                       'Basic realm="payload"'})
        self.record(int(HTTPStatus.UNAUTHORIZED), "denied")
        return False

    def respond(self, status: int, body: bytes, content_type: str = "text/plain",
                extra: Optional[Dict[str, str]] = None, head_only: bool = False) -> int:
        """Send a complete response.

        Args:
            status: HTTP status.
            body: response body.
            content_type: MIME type.
            extra: additional headers.
            head_only: send headers but no body (for HEAD).

        Returns:
            The number of body bytes sent.
        """
        try:
            self.send_response(int(status))
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Server", self.server_version)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if not head_only and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return 0
        return len(body)

    # -- endpoints --------------------------------------------------------- #
    def do_HEAD(self) -> None:  # noqa: N802 - http.server naming
        """Handle HEAD by running GET without the body."""
        self.do_GET(head_only=True)

    def do_GET(self, head_only: bool = False) -> None:  # noqa: N802
        """Serve a file, a template or one of the collection endpoints.

        Args:
            head_only: True when called from HEAD.
        """
        state = self.state
        if not self.require_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path

        if route in ("/callback", "/pixel.gif", "/open.gif"):
            state.counter("callbacks")
            with state.lock:
                state.callbacks.append({
                    "timestamp": now_iso(), "client": self.client_ip(),
                    "user_agent": self.headers.get("User-Agent", ""),
                    "query": parsed.query, "path": route,
                })
            sent = self.respond(HTTPStatus.OK, PIXEL_GIF, "image/gif",
                                extra={"Cache-Control": "no-store, no-cache"}, head_only=head_only)
            self.record(int(HTTPStatus.OK), "callback", sent)
            return

        if route == "/ping":
            sent = self.respond(HTTPStatus.NO_CONTENT, b"", head_only=head_only)
            self.record(int(HTTPStatus.NO_CONTENT), "callback", sent)
            return

        if route == "/status":
            payload = json.dumps(state.summary(), indent=2).encode()
            sent = self.respond(HTTPStatus.OK, payload, "application/json", head_only=head_only)
            self.record(int(HTTPStatus.OK), "status", sent)
            return

        if route.startswith("/template/"):
            name = route[len("/template/"):]
            sent = self.serve_template(name, head_only=head_only)
            self.record(int(HTTPStatus.OK) if sent else int(HTTPStatus.NOT_FOUND),
                        "template", sent)
            return

        if route in ("/", "/index.html"):
            sent = self.serve_index(head_only=head_only)
            self.record(int(HTTPStatus.OK), "index", sent)
            return

        sent = self.serve_file(route, head_only=head_only)
        return

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        """Handle an upload posted by a client."""
        state = self.state
        if not self.require_auth():
            return
        if state.read_only:
            self.respond(HTTPStatus.FORBIDDEN, b"server is read-only\n")
            self.record(int(HTTPStatus.FORBIDDEN), "denied")
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in ("/upload", "/collect", "/"):
            self.respond(HTTPStatus.NOT_FOUND, b"no such endpoint\n")
            self.record(int(HTTPStatus.NOT_FOUND), "denied")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            self.respond(HTTPStatus.BAD_REQUEST, b"empty upload\n")
            self.record(int(HTTPStatus.BAD_REQUEST), "denied")
            return
        if length > state.max_upload_bytes:
            self.respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                         f"limit is {human_bytes(state.max_upload_bytes)}\n".encode())
            self.record(int(HTTPStatus.REQUEST_ENTITY_TOO_LARGE), "denied")
            return

        requested = urllib.parse.unquote(self.headers.get("X-Filename", "")
                                         or parsed.path.rsplit("/", 1)[-1] or "upload")
        safe_name = "".join(character for character in os.path.basename(requested)
                            if character.isalnum() or character in "._-") or "upload"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        upload_dir = state.upload_dir or Path.cwd()
        upload_dir.mkdir(parents=True, exist_ok=True)
        target = upload_dir / f"{stamp}_{self.client_ip().replace(':', '_')}_{safe_name}"

        received = 0
        digest = hashlib.sha256()
        try:
            with target.open("wb") as handle:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    remaining -= len(chunk)
        except OSError as exc:
            self.respond(HTTPStatus.INTERNAL_SERVER_ERROR,
                         f"could not store the upload: {exc}\n".encode())
            self.record(int(HTTPStatus.INTERNAL_SERVER_ERROR), "denied")
            return

        entry = {
            "timestamp": now_iso(),
            "client": self.client_ip(),
            "filename": safe_name,
            "stored_as": target.name,
            "bytes": received,
            "sha256": digest.hexdigest(),
            "user_agent": self.headers.get("User-Agent", ""),
        }
        with state.lock:
            state.uploads.append(entry)
        self.respond(HTTPStatus.OK, f"stored {received} byte(s)\n".encode(),
                     extra={"X-SHA256": entry["sha256"]})
        self.record(int(HTTPStatus.OK), "upload", received)
        if state.database is not None:
            try:
                state.database.event("payload_server", "payload",
                                     f"upload {safe_name} ({human_bytes(received)}) "
                                     f"from {entry['client']}", "INFO", data=entry)
            except Exception:  # pragma: no cover
                pass

    # -- rendering --------------------------------------------------------- #
    def serve_index(self, head_only: bool = False) -> int:
        """Render the delivery landing page.

        Args:
            head_only: True when called from HEAD.

        Returns:
            Bytes sent.
        """
        state = self.state
        root = state.payload_dir or Path.cwd()
        entries = list_payloads(root)
        rows = []
        for entry in entries:
            size = human_bytes(entry["size"])
            rows.append(
                f"<tr><td><a href=\"/{urllib.parse.quote(entry['name'])}\">"
                f"{entry['name']}</a></td><td class=\"num\">{size}</td>"
                f"<td class=\"hash\">{entry['sha256'][:16]}</td></tr>")
        if not rows:
            rows.append("<tr><td colspan=\"3\">no payloads staged yet - drop files "
                        "into the staging directory</td></tr>")
        templates = "".join(
            f"<li><a href=\"/template/{urllib.parse.quote(name)}\">{name}</a></li>"
            for name in sorted(state.templates))
        body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>cyberdeck payload server</title>
<style>
 body {{ background:#080b10; color:#b9f2ff; font-family:"DejaVu Sans Mono",monospace;
        margin:0; padding:2rem; }}
 h1 {{ color:#39ff14; letter-spacing:.1em; font-size:1.15rem; }}
 table {{ border-collapse:collapse; width:100%; margin-top:1rem; }}
 th, td {{ text-align:left; padding:.35rem .5rem; border-bottom:1px solid #123; }}
 th {{ color:#39ff14; font-weight:normal; }}
 a {{ color:#7fd7ff; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
 .num {{ text-align:right; }} .hash {{ color:#4a7a80; font-size:.85em; }}
 footer {{ margin-top:1.5rem; color:#3f6b72; font-size:.8em; }}
</style></head>
<body>
<h1>◈ cyberdeck payload delivery ◈</h1>
<p>engagement: {state.variables.get("engagement", "n/a")} ·
   reference: {state.variables.get("reference", "n/a")} ·
   started: {state.started}</p>
<table><thead><tr><th>payload</th><th class="num">size</th><th>sha256</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2 style="font-size:1rem;color:#39ff14;margin-top:1.4rem;">delivery pages</h2>
<ul>{templates or "<li>none</li>"}</ul>
<footer>served by cyberdeck-arsenal {VERSION} · every request is logged</footer>
</body></html>
"""
        return self.respond(HTTPStatus.OK, body.encode(), "text/html; charset=utf-8",
                            head_only=head_only)

    def serve_template(self, name: str, head_only: bool = False) -> int:
        """Render a delivery template with the engagement variables.

        Args:
            name: template file name.
            head_only: True when called from HEAD.

        Returns:
            Bytes sent (0 when the template does not exist).
        """
        state = self.state
        template = state.templates.get(name) or state.templates.get(Path(name).name)
        if template is None:
            self.respond(HTTPStatus.NOT_FOUND, b"no such template\n")
            return 0
        rendered = template
        for key, value in state.variables.items():
            rendered = rendered.replace("{" + key + "}", value)
        if "{" + "payload" + "}" in rendered:
            first = list_payloads(state.payload_dir or Path.cwd())
            rendered = rendered.replace("{payload}", first[0]["name"] if first else "")
        return self.respond(HTTPStatus.OK, rendered.encode(),
                            "text/html; charset=utf-8", head_only=head_only)

    def serve_file(self, route: str, head_only: bool = False) -> int:
        """Serve a staged payload with range support.

        Args:
            route: the URL path.
            head_only: True when called from HEAD.

        Returns:
            Bytes sent.
        """
        state = self.state
        root = state.payload_dir or Path.cwd()
        target = safe_join(root, route)
        if target is None:
            body = b"forbidden\n" if urllib.parse.unquote(route).startswith("/.") else b"not found\n"
            status = HTTPStatus.FORBIDDEN if body.startswith(b"forbidden") else HTTPStatus.NOT_FOUND
            self.respond(status, body)
            self.record(int(status), "denied")
            return 0
        if not target.exists():
            # Nicely 404 both the raw and the encoded form of a traversal attempt
            self.respond(HTTPStatus.NOT_FOUND, b"not found\n")
            self.record(int(HTTPStatus.NOT_FOUND), "denied")
            return 0
        if target.is_dir():
            index = target / "index.html"
            if index.is_file():
                target = index
            else:
                body = self.render_directory(target)
                sent = self.respond(HTTPStatus.OK, body, "text/html; charset=utf-8",
                                    head_only=head_only)
                self.record(int(HTTPStatus.OK), "listing", sent)
                return sent

        size = target.stat().st_size
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        start, end = 0, size - 1
        range_header = self.headers.get("Range", "")
        status = HTTPStatus.OK
        if range_header.startswith("bytes="):
            spec = range_header[6:].split(",")[0].strip()
            low, _, high = spec.partition("-")
            try:
                if low:
                    start = int(low)
                if high:
                    end = min(size - 1, int(high))
                if not low and high:
                    start = max(0, size - int(high))
                    end = size - 1
            except ValueError:
                start, end = 0, size - 1
            if start > end or start >= size:
                self.respond(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE, b"",
                             extra={"Content-Range": f"bytes */{size}"})
                self.record(int(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE), "range")
                return 0
            status = HTTPStatus.PARTIAL_CONTENT

        length = end - start + 1
        extra = {
            "Accept-Ranges": "bytes",
            "Last-Modified": email.utils.formatdate(target.stat().st_mtime, usegmt=True),
            "X-SHA256": sha256_of(target),
        }
        if status == HTTPStatus.PARTIAL_CONTENT:
            extra["Content-Range"] = f"bytes {start}-{end}/{size}"
        try:
            self.send_response(int(status))
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            sent = 0
            if not head_only:
                with target.open("rb") as handle:
                    handle.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = handle.read(min(1 << 16, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        sent += len(chunk)
                        remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            sent = 0
        self.record(int(status), "file", sent)
        return sent

    def render_directory(self, directory: Path) -> bytes:
        """Render a simple directory listing for a subdirectory.

        Args:
            directory: the directory to list.

        Returns:
            The HTML page.
        """
        rows = []
        for entry in sorted(directory.iterdir()):
            if entry.name.startswith("."):
                continue
            suffix = "/" if entry.is_dir() else ""
            size = "" if entry.is_dir() else human_bytes(entry.stat().st_size)
            root = self.state.payload_dir or Path.cwd()
            try:
                href = urllib.parse.quote(str(entry.relative_to(root)))
            except ValueError:
                continue
            rows.append(f"<li><a href=\"/{href}\">{entry.name}{suffix}</a> "
                        f"<span class=\"num\">{size}</span></li>")
        body = ("<!doctype html><html><head><meta charset=\"utf-8\">"
                "<title>index of " + str(directory.name) + "</title></head>"
                "<body style=\"background:#080b10;color:#b9f2ff;"
                "font-family:monospace;padding:2rem\"><h1 style=\"color:#39ff14;"
                "font-size:1rem\">" + str(directory.name) + "/</h1><ul>"
                + "".join(rows) + "</ul></body></html>")
        return body.encode()

class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """A threaded HTTP server that shuts down promptly."""

    daemon_threads = True
    allow_reuse_address = True


def load_templates(directory: Path, staging: Path, logger: Logger) -> Dict[str, str]:
    """Load delivery templates, writing the built-in ones when missing.

    Args:
        directory: the template directory (``data/templates``).
        staging: the payload staging directory.
        logger: shared logger.

    Returns:
        A mapping of template name to content.
    """
    templates: Dict[str, str] = {}
    for name, content in DELIVERY_TEMPLATES.items():
        path = directory / name
        if path.is_file():
            try:
                templates[name] = path.read_text(errors="replace")
                continue
            except OSError as exc:
                logger.debug("could not read %s: %s", path, exc)
        templates[name] = content
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        except OSError as exc:
            logger.debug("could not write %s: %s", path, exc)
    del staging
    return templates


def make_certificate(directory: Path, hostname: str, logger: Logger
                     ) -> Optional[Path]:
    """Generate a self-signed certificate for HTTPS.

    Args:
        directory: where to write the certificate and key.
        hostname: the common name / SAN for the certificate.
        logger: shared logger.

    Returns:
        The certificate path, or ``None`` when openssl is unavailable.
    """
    if shutil.which("openssl") is None:
        logger.error("openssl is not installed - cannot create a certificate")
        logger.info("install it with: sudo pacman -S openssl")
        return None
    directory.mkdir(parents=True, exist_ok=True)
    certificate = directory / "payload-server.crt"
    key = directory / "payload-server.key"
    if certificate.is_file() and key.is_file():
        return certificate
    command = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(certificate),
        "-days", "30", "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName=DNS:{hostname},IP:127.0.0.1",
    ]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("openssl failed: %s", exc)
        return None
    if result.returncode != 0 or not certificate.is_file():
        logger.error("could not create the certificate: %s",
                     result.stderr.decode(errors="replace").strip()[:200])
        return None
    try:
        key.chmod(0o600)
        certificate.chmod(0o644)
    except OSError:  # pragma: no cover
        pass
    logger.ok("self-signed certificate written to %s (valid 30 days)", certificate.parent)
    return certificate


def free_port(preferred: int) -> int:
    """Return a usable TCP port, falling back when the preferred one is taken.

    Args:
        preferred: the port to try first.

    Returns:
        The port to bind.
    """
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("0.0.0.0", candidate))
                return probe.getsockname()[1]
            except OSError:
                continue
    return preferred


def serve(args: argparse.Namespace, config: Config, logger: Logger) -> int:
    """Run the server until the duration expires or a signal arrives.

    Args:
        args: parsed command line.
        config: loaded cyberdeck configuration.
        logger: shared logger.

    Returns:
        Process exit code.
    """
    install_dir = Path(str(config.get("general.install_dir", "/opt/cyberdeck-arsenal")))
    staging = (args.staging or (install_dir / "payloads")).resolve()
    staging.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = install_dir / "captures" / "payload" / stamp
    upload_dir = session_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    state = ServerState(
        logfile=session_dir / "requests.jsonl",
        upload_dir=upload_dir,
        payload_dir=staging,
        variables={
            "engagement": args.engagement or str(config.get("general.operator_name",
                                                             "authorised engagement")),
            "reference": args.reference or stamp,
            "generated": now_iso(),
            "deadline": args.deadline or "close of business today",
            "command": args.command or "the instructions provided by your helpdesk",
            "payload": args.file or "",
        },
        max_upload_bytes=args.max_upload,
        read_only=args.read_only,
        hash_uploads=not args.no_hash,
        logger=logger,
    )
    templates_dir = Path(__file__).resolve().parent.parent / "data" / "templates"
    installed_templates = install_dir / "data" / "templates"
    state.templates = load_templates(
        installed_templates if installed_templates.is_dir() else templates_dir,
        staging, logger)
    if args.auth:
        user, _, password = args.auth.partition(":")
        state.auth = (user, password)
    try:
        state.database = Database("events")
    except Exception as exc:  # pragma: no cover
        logger.debug("events database unavailable: %s", exc)

    handler = type("BoundPayloadHandler", (PayloadHandler,), {"state": state})
    port = free_port(args.port)
    if port != args.port:
        logger.warn("port %d is in use - using %d instead", args.port, port)
    try:
        httpd = ThreadedServer((args.bind, port), handler)
    except OSError as exc:
        logger.error("could not bind %s:%d - %s", args.bind, port, exc)
        return 1

    scheme = "https" if args.tls else "http"
    if args.tls:
        certificate = make_certificate(session_dir, args.hostname, logger)
        if certificate is None:
            httpd.server_close()
            return 1
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(certificate),
                                keyfile=str(certificate.with_suffix(".key")))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    url_host = args.hostname if args.hostname else socket.gethostname()
    logger.ok("payload server listening on %s://%s:%d", scheme, args.bind, port)
    print()
    print(colour(f"  staging directory : {staging}", "bold"))
    print(f"  session directory : {session_dir}")
    print(f"  landing page      : {scheme}://{url_host}:{port}/")
    print(f"  collection        : {scheme}://{url_host}:{port}/upload "
          f"(POST), /callback, /ping")
    print(f"  status            : {scheme}://{url_host}:{port}/status")
    if state.auth:
        print(colour(f"  basic auth        : enabled for user {state.auth[0]}", "yellow"))
    if args.read_only:
        print(colour("  read-only         : uploads are refused", "yellow"))
    print()
    logger.warn("only serve payloads to systems you are authorised to test; every "
                "request is logged with the client address")

    stop = threading.Event()

    def shutdown(_signum: int, _frame: Any) -> None:
        logger.info("stopping the payload server")
        stop.set()

    for name in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, name), shutdown)
        except (ValueError, OSError):  # pragma: no cover
            pass

    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5},
                              daemon=True)
    thread.start()
    deadline = time.time() + args.duration if args.duration else None
    try:
        while not stop.is_set():
            if deadline and time.time() >= deadline:
                logger.info("capture window of %ss elapsed", args.duration)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)

    summary = state.summary()
    write_session_report(session_dir, summary, state, staging)
    if state.database is not None:
        try:
            state.database.event("payload_server", "payload",
                                 f"session finished: {summary['requests']} request(s), "
                                 f"{len(state.uploads)} upload(s), "
                                 f"{human_bytes(summary['bytes_served'])} served",
                                 "INFO", data={"session_dir": str(session_dir)})
        except Exception:  # pragma: no cover
            pass
        finally:
            try:
                state.database.close()
            except Exception:  # pragma: no cover
                pass

    if not args.no_custody:
        seal_evidence(session_dir, logger)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print()
        logger.ok("session finished: %d request(s) from %d client(s), %d upload(s), "
                  "%d callback(s)", summary["requests"], summary["unique_clients"],
                  len(state.uploads), len(state.callbacks))
        logger.info("artefacts: %s", session_dir)
    return 0


def write_session_report(session_dir: Path, summary: Dict[str, Any], state: ServerState,
                         staging: Path) -> Dict[str, Path]:
    """Write the JSON summary, upload index, CSV and Markdown report.

    Args:
        session_dir: where the session artefacts live.
        summary: the summary dictionary.
        state: the server state (for the ingest lists).
        staging: the staging directory that was served.

    Returns:
        A mapping of artefact name to path.
    """
    session_dir.mkdir(parents=True, exist_ok=True)
    artefacts: Dict[str, Path] = {}

    summary_path = session_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    artefacts["json"] = summary_path

    uploads_path = session_dir / "uploads.jsonl"
    with uploads_path.open("w") as handle:
        for entry in state.uploads:
            handle.write(json.dumps(entry) + "\n")
    artefacts["uploads"] = uploads_path

    csv_path = session_dir / "requests.csv"
    with csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "client", "method", "path", "status", "bytes",
                         "user_agent", "referer", "query", "note"])
        for record in state.requests:
            writer.writerow([record.timestamp, record.client, record.method, record.path,
                             record.status, record.bytes_sent, record.user_agent,
                             record.referer, record.query, record.note])
    artefacts["csv"] = csv_path

    lines = [
        "# Payload server session",
        "",
        f"- started: {summary['started']}",
        f"- uptime: {summary['uptime_s']}s",
        f"- staging directory: `{staging}`",
        f"- requests: {summary['requests']}",
        f"- bytes served: {human_bytes(summary['bytes_served'])}",
        f"- unique clients: {summary['unique_clients']}",
        f"- uploads received: {len(state.uploads)}",
        f"- callbacks: {len(state.callbacks)}",
        "",
        "## Clients",
        "",
        "| client | requests |",
        "| --- | --- |",
    ]
    for client, count in sorted(summary["clients"].items(), key=lambda item: -item[1]):
        lines.append(f"| {client} | {count} |")
    lines += ["", "## Paths served", "", "| path | hits |", "| --- | --- |"]
    for path, count in sorted(summary["paths"].items(), key=lambda item: -item[1])[:25]:
        lines.append(f"| `{path}` | {count} |")
    if state.uploads:
        lines += ["", "## Uploads", "",
                  "| when | client | file | bytes | sha256 |", "| --- | --- | --- | --- | --- |"]
        for entry in state.uploads:
            lines.append(f"| {entry['timestamp']} | {entry['client']} | "
                         f"{entry['stored_as']} | {entry['bytes']} | "
                         f"`{entry['sha256'][:24]}` |")
    if state.callbacks:
        lines += ["", "## Callbacks", "",
                  "| when | client | user agent |", "| --- | --- | --- |"]
        for entry in state.callbacks[:50]:
            lines.append(f"| {entry['timestamp']} | {entry['client']} | "
                         f"{entry['user_agent'][:60]} |")
    lines += ["", "---", "",
              "Every entry above is also in `requests.jsonl` (one JSON object per "
              "line) and in the shared events database."]
    report = session_dir / "SUMMARY.md"
    report.write_text("\n".join(lines) + "\n")
    artefacts["markdown"] = report
    return artefacts


def seal_evidence(session_dir: Path, logger: Logger) -> Optional[str]:
    """Seal the session directory with the shared custody hasher.

    Args:
        session_dir: the directory to seal.
        logger: shared logger.

    Returns:
        The custody log path when sealing succeeded, otherwise ``None``.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / "recon" / "reporting" / "evidence_hasher.py",
        Path("/opt/cyberdeck-arsenal/recon/reporting/evidence_hasher.py"),
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        command = [sys.executable, str(candidate), "seal", str(session_dir),
                   "--note", f"payload server session {session_dir.name}"]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warn("could not seal the evidence: %s", exc)
            return None
        if result.returncode == 0:
            logger.ok("evidence sealed with the chain of custody")
            return (session_dir / "manifest.sha256").as_posix()
        logger.warn("evidence sealing failed: %s",
                    result.stdout.decode(errors="replace").strip()[:200])
        return None
    logger.debug("evidence_hasher.py not found - skipping the seal")
    return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="payload_server.py",
        description="Authorised payload delivery server with request logging",
        epilog="only serve payloads to systems covered by your authorisation")
    parser.add_argument("--version", action="version", version=f"payload_server {VERSION}")
    parser.add_argument("--bind", default="0.0.0.0", help="address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="port (default: 8080)")
    parser.add_argument("--hostname", default="", help="hostname to advertise and put in the certificate")
    parser.add_argument("--duration", type=int, default=0,
                        help="seconds to serve (0 = until interrupted)")
    parser.add_argument("--staging", type=Path, default=None,
                        help="directory to serve (default: <install>/payloads)")
    parser.add_argument("--file", default="", help="the payload the templates should link to")
    parser.add_argument("--engagement", default="", help="engagement or client name for the templates")
    parser.add_argument("--reference", default="", help="reference shown on the delivery pages")
    parser.add_argument("--deadline", default="", help="deadline shown in the invoice template")
    parser.add_argument("--command", default="", help="command shown in the update template")
    parser.add_argument("--auth", default="", help="require basic auth: user:password")
    parser.add_argument("--tls", action="store_true", help="serve HTTPS with a self-signed certificate")
    parser.add_argument("--read-only", action="store_true", help="refuse uploads")
    parser.add_argument("--no-hash", action="store_true",
                        help="do not SHA-256 uploads as they arrive")
    parser.add_argument("--no-custody", action="store_true",
                        help="skip sealing the session with the chain of custody")
    parser.add_argument("--max-upload", type=int, default=64 * 1024 * 1024,
                        help="maximum upload size in bytes (default: 64 MiB)")
    parser.add_argument("--list", action="store_true", help="list the staged payloads and exit")
    parser.add_argument("--check", action="store_true", help="validate staging and permissions")
    parser.add_argument("--json", action="store_true", help="emit the session summary as JSON")
    parser.add_argument("--from-service", action="store_true", help="service-friendly output")
    parser.add_argument("--quiet", "-q", action="store_true", help="warnings and errors only")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the payload server.

    Args:
        argv: argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = build_parser().parse_args(argv)
    config = Config().load()
    logger = Logger("payload_server",
                    level=str(config.get("general.log_level", "INFO")),
                    quiet=args.quiet or args.from_service or args.json)
    if not (args.from_service or args.quiet or args.json):
        logger.banner("payload server", f"v{VERSION} · delivery and collection")

    install_dir = Path(str(config.get("general.install_dir", "/opt/cyberdeck-arsenal")))
    staging = (args.staging or (install_dir / "payloads")).resolve()

    if args.list:
        entries = list_payloads(staging)
        if not entries:
            logger.info("nothing staged in %s", staging)
            return 3
        print()
        print(f"  {'PAYLOAD':<40}{'SIZE':>10}  {'MODIFIED':<20}SHA256")
        print("  " + "─" * 96)
        for entry in entries:
            print(f"  {entry['name'][:38]:<40}{human_bytes(entry['size']):>10}  "
                  f"{entry['modified']:<20}{entry['sha256'][:24]}")
        print()
        return 0

    if args.check:
        problems = 0
        print()
        print(colour("  payload server pre-flight", "bold"))
        if not staging.exists():
            logger.warn("staging directory %s does not exist", staging)
            try:
                staging.mkdir(parents=True, exist_ok=True)
                logger.ok("created %s", staging)
            except OSError as exc:
                logger.error("cannot create it: %s", exc)
                problems += 1
        if not os.access(staging, os.R_OK):
            logger.error("%s is not readable by this user", staging)
            problems += 1
        if shutil.which("openssl") is None and args.tls:
            logger.error("--tls was requested but openssl is missing")
            problems += 1
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind((args.bind, args.port))
            logger.ok("port %d is free on %s", args.port, args.bind)
        except OSError as exc:
            logger.error("cannot bind %s:%d - %s", args.bind, args.port, exc)
            problems += 1
        entries = list_payloads(staging)
        logger.info("%d payload(s) staged (%s)", len(entries),
                    human_bytes(sum(entry["size"] for entry in entries)))
        if bool(config.get("general.authorised_use_acknowledged", False)):
            logger.ok("legal acknowledgement is recorded in cyberdeck.conf")
        else:
            logger.warn("the legal acknowledgement is not set - run 'cdeck config'")
        print()
        return 1 if problems else 0

    if not require_acknowledgement(config, logger):
        logger.error("authorisation not acknowledged - refusing to start")
        return 2
    if not confirm("Start the payload server on "
                   f"{args.bind}:{args.port}?", default=True, logger=logger):
        logger.info("aborted")
        return 0
    return serve(args, config, logger)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
