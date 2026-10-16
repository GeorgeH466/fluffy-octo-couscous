#!/usr/bin/env python3
"""
osint_gatherer.py - OSINT collection for cyberdeck-arsenal
==========================================================

Description
-----------
Collects open-source intelligence about a domain, username or email address
using only public sources and installed tooling:

    * email harvesting       - theHarvester wrapper (modules: bing, duckduckgo,
                               crtsh, hackertarget, otx, urlscan)
    * domain intelligence    - DNS records, WHOIS, certificate transparency
                               (crt.sh), HTTP fingerprint, robots.txt/sitemap
    * subdomain enumeration  - crt.sh + subfinder when available
    * username search        - presence check across ~20 popular platforms
                               (HTTP status only, no authentication attempts)
    * metadata extraction    - EXIF/document metadata from files you already
                               possess (public documents you downloaded)

Everything is written to a timestamped engagement directory with a markdown
summary and a JSON export.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; requests; theHarvester, subfinder, exiftool (optional)
Licence     : MIT - only use against targets you are authorised to investigate,
              and respect the terms of service of every third-party platform.

Usage
-----
    cdeck osint example.com
    python3 recon/active/osint_gatherer.py --username jsmith
    python3 recon/active/osint_gatherer.py --domain example.com --emails
    python3 recon/active/osint_gatherer.py --metadata ~/Downloads/report.pdf
    python3 recon/active/osint_gatherer.py --json --domain example.com
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

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
        C, Config, Database, Logger, colour, deps, engagement_dir, now_iso, run, write_json,
    )
except ImportError as exc:
    print(f"osint_gatherer: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"
USER_AGENT = f"cyberdeck-arsenal/{__version__} OSINT module"

#: Platforms checked for username presence. All checks are unauthenticated HTTP
#: GETs; a 200 response means "the profile page exists", not "this is the person".
USERNAME_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("GitHub", "https://github.com/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}"),
    ("Keybase", "https://keybase.io/{u}"),
    ("Docker Hub", "https://hub.docker.com/u/{u}"),
    ("PyPI", "https://pypi.org/user/{u}/"),
    ("NPM", "https://www.npmjs.com/~{u}"),
    ("SoundCloud", "https://soundcloud.com/{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("Steam", "https://steamcommunity.com/id/{u}"),
    ("Patreon", "https://www.patreon.com/{u}"),
    ("Telegram", "https://t.me/{u}"),
    ("Mastodon (mastodon.social)", "https://mastodon.social/@{u}"),
    ("BitBucket", "https://bitbucket.org/{u}/"),
    ("HackTheBox", "https://app.hackthebox.com/users/{u}"),
    ("TryHackMe", "https://tryhackme.com/p/{u}"),
    ("Imgur", "https://imgur.com/user/{u}"),
    ("Medium", "https://medium.com/@{u}"),
    ("Dev.to", "https://dev.to/{u}"),
    ("Behance", "https://www.behance.net/{u}"),
    ("About.me", "https://about.me/{u}"),
)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@dataclass
class OsintResult:
    """Aggregated OSINT findings."""

    target: str = ""
    kind: str = "domain"
    generated: str = field(default_factory=now_iso)
    emails: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    whois_summary: str = ""
    http_fingerprint: Dict[str, str] = field(default_factory=dict)
    certificates: List[Dict[str, str]] = field(default_factory=list)
    usernames_found: List[Tuple[str, str]] = field(default_factory=list)
    usernames_checked: int = 0
    metadata: List[Dict[str, Any]] = field(default_factory=list)
    robots: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for JSON export."""
        return {
            "target": self.target, "kind": self.kind, "generated": self.generated,
            "emails": self.emails, "subdomains": self.subdomains,
            "dns_records": self.dns_records, "whois_summary": self.whois_summary,
            "http_fingerprint": self.http_fingerprint, "certificates": self.certificates,
            "usernames_found": [{"platform": platform, "url": url}
                                for platform, url in self.usernames_found],
            "usernames_checked": self.usernames_checked,
            "metadata": self.metadata, "robots": self.robots,
            "sitemap_urls": self.sitemap_urls, "notes": self.notes, "errors": self.errors,
        }


class OsintGatherer:
    """Runs the collection modules."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None,
                 timeout: float = 15.0) -> None:
        """Prepare the gatherer (HTTP session, target directories)."""
        self.config = config or Config().load()
        self.logger = logger or Logger("osint_gatherer",
                                       str(self.config.get("general.log_level", "INFO")))
        self.timeout = timeout
        self.session: Optional[Any] = None
        if deps.have_module("requests"):
            import requests  # type: ignore
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT})
        else:
            self.logger.warn("requests is not installed - HTTP-based collection is limited")

    # -- HTTP helpers ------------------------------------------------------- #
    def _get(self, url: str, params: Optional[Dict[str, Any]] = None,
             allow_redirects: bool = True, timeout: Optional[float] = None) -> Optional[Any]:
        """GET a URL, returning the response or None (never raises)."""
        if not self.session:
            return None
        try:
            return self.session.get(url, params=params or {}, timeout=timeout or self.timeout,
                                    allow_redirects=allow_redirects)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"GET {url} failed: {exc}")
            return None

    # -- domain intelligence ------------------------------------------------ #
    def dns_records(self, domain: str, result: OsintResult) -> None:
        """Collect DNS records with dig (or socket-based fallbacks)."""
        types = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME")
        if deps.have("dig"):
            for record_type in types:
                code, out, _ = run(["dig", "+short", record_type, domain], timeout=15)
                values = [line.strip() for line in (out or "").splitlines() if line.strip()]
                if values:
                    result.dns_records[record_type] = values
            self.logger.ok(f"DNS: {', '.join(f'{k}({len(v)})' for k, v in result.dns_records.items())}")
        else:
            self.logger.warn("dig not installed - falling back to basic resolution")
            try:
                result.dns_records["A"] = sorted({info[4][0] for info in socket.getaddrinfo(
                    domain, None, proto=socket.IPPROTO_TCP)})
            except socket.gaierror as exc:
                result.errors.append(f"DNS resolution failed: {exc}")

        # MX -> mail provider insight
        for mx in result.dns_records.get("MX", []):
            lowered = mx.lower()
            for provider in ("google", "outlook", "protection.outlook", "mimecast",
                             "protonmail", "zoho", "fastmail", "cloudflare"):
                if provider in lowered:
                    result.notes.append(f"mail is handled by {provider} ({mx})")
                    break

    def whois_lookup(self, domain: str, result: OsintResult) -> None:
        """Run whois and extract the fields that matter."""
        if not deps.have("whois"):
            result.errors.append("whois not installed")
            return
        code, out, err = run(["whois", domain], timeout=45)
        if code != 0 or not out:
            result.errors.append(f"whois failed for {domain}: {(err or '').strip()[:120]}")
            return
        interesting = ("Registrar:", "Creation Date", "Registry Expiry Date", "Expiry Date",
                       "Updated Date", "Registrant Organization", "Registrant Country",
                       "Name Server", "Domain Status", "DNSSEC")
        lines = []
        for line in out.splitlines():
            if any(line.strip().lower().startswith(token.lower()) for token in interesting):
                lines.append(line.strip())
        if not lines:
            lines = out.splitlines()[:15]
        result.whois_summary = "\n".join(lines[:30])
        if "clientTransferProhibited" not in out and "Domain Status" in out:
            result.notes.append("domain lock status unclear - check transfer protection")
        self.logger.ok(f"whois: {len(lines)} relevant line(s)")

    def harvester(self, domain: str, result: OsintResult, output_dir: Path) -> None:
        """Run theHarvester for email addresses and hostnames."""
        binary = "theHarvester"
        if not deps.have(binary):
            result.notes.append("theHarvester not installed - email harvesting skipped "
                                "(pacman -S theharvester)")
            return
        outfile = output_dir / "raw" / f"harvester_{domain}.html"
        command = [binary, "-d", domain, "-b", "duckduckgo,crtsh,hackertarget,otx,urlscan",
                   "-f", str(outfile.with_suffix("")), "-l", "300"]
        self.logger.info("running theHarvester (this takes 30-90 seconds)")
        code, out, err = run(command, timeout=300, logger=self.logger)
        text = f"{out}\n{err}"
        for email in set(EMAIL_RE.findall(text)):
            if email.lower().endswith(domain.lower()) or domain.lower() in email.lower():
                result.emails.append(email)
        # Hostnames theHarvester printed
        for line in text.splitlines():
            match = re.match(r"^\[?\]?\s*([a-z0-9][a-z0-9.\-]*\.%s)\s*$" % re.escape(domain),
                             line.strip(), re.IGNORECASE)
            if match:
                result.subdomains.append(match.group(1).lower())
        if outfile.exists():
            result.notes.append(f"theHarvester report: {outfile.name}")
        result.emails = sorted(set(result.emails))
        self.logger.ok(f"theHarvester: {len(result.emails)} email(s), "
                       f"{len(set(result.subdomains))} host(s)")

    def crt_sh(self, domain: str, result: OsintResult) -> None:
        """Query certificate transparency logs (crt.sh) for subdomains."""
        response = self._get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                             timeout=45)
        if not response or response.status_code != 200:
            result.notes.append("crt.sh query failed or was rate limited")
            return
        try:
            entries = response.json()
        except ValueError:
            result.notes.append("crt.sh returned non-JSON (likely rate limited)")
            return
        names: set = set()
        certificates: List[Dict[str, str]] = []
        for entry in entries[:400]:
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lower()
                if name and name.endswith(domain.lower()) and "*" not in name:
                    names.add(name)
            if len(certificates) < 25:
                certificates.append({
                    "common_name": str(entry.get("common_name", "")),
                    "issuer": str(entry.get("issuer_name", ""))[:120],
                    "not_before": str(entry.get("not_before", "")),
                    "not_after": str(entry.get("not_after", "")),
                    "serial": str(entry.get("serial_number", "")),
                })
        result.subdomains.extend(sorted(names))
        result.certificates = certificates
        self.logger.ok(f"certificate transparency: {len(names)} unique name(s)")

    def subfinder(self, domain: str, result: OsintResult) -> None:
        """Run subfinder when available (passive, no brute forcing)."""
        if not deps.have("subfinder"):
            return
        code, out, _ = run(["subfinder", "-d", domain, "-silent", "-all"], timeout=300)
        for line in (out or "").splitlines():
            candidate = line.strip().lower()
            if candidate.endswith(domain.lower()):
                result.subdomains.append(candidate)
        self.logger.ok(f"subfinder contributed {len((out or '').splitlines())} host(s)")

    def web_fingerprint(self, domain: str, result: OsintResult) -> None:
        """Collect robots.txt, sitemap.xml, HTTP headers and interesting paths."""
        base = f"https://{domain}"
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            response = self._get(url, timeout=15)
            if response is not None:
                base = url
                headers = {key: value for key, value in response.headers.items()}
                result.http_fingerprint = {
                    "url": str(response.url),
                    "status": str(response.status_code),
                    "server": headers.get("Server", "unknown"),
                    "powered_by": headers.get("X-Powered-By", "unknown"),
                    "frameworks": ", ".join(
                        value for key, value in headers.items()
                        if key.lower() in ("x-generator", "x-drupal-cache", "x-aspnet-version",
                                           "x-shopify-stage", "x-vercel-id")),
                }
                break
        # robots.txt can leak internal paths
        robots = self._get(f"{base}/robots.txt", timeout=10)
        if robots is not None and robots.status_code == 200:
            result.robots = [line.strip() for line in robots.text.splitlines()[:60]]
            for line in result.robots:
                if line.lower().startswith("disallow:") and len(line) > 12:
                    path = line.split(":", 1)[1].strip()
                    if path not in ("/", ""):
                        result.notes.append(f"robots.txt disallows {path} - often an interesting path")
        # sitemap.xml leaks URL structure
        sitemap = self._get(f"{base}/sitemap.xml", timeout=10)
        if sitemap is not None and sitemap.status_code == 200:
            result.sitemap_urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap.text)[:60]
            result.notes.append(f"sitemap.xml exposes {len(result.sitemap_urls)} URL(s)")

    # -- username search ---------------------------------------------------- #
    def search_username(self, username: str, result: OsintResult,
                        delay: float = 0.4) -> None:
        """Check username presence across known platforms (unauthenticated GETs)."""
        if not self.session:
            result.errors.append("requests not installed - username search unavailable")
            return
        self.logger.info(f"checking username '{username}' on "
                         f"{len(USERNAME_PLATFORMS)} platform(s)")
        for platform, template in USERNAME_PLATFORMS:
            url = template.format(u=username)
            result.usernames_checked += 1
            response = self._get(url, allow_redirects=True, timeout=12)
            if response is None:
                continue
            if response.status_code == 200:
                text = response.text.lower()
                # Reduce false positives on platforms that return 200 for "not found"
                not_found_markers = ("user not found", "page not found", "no such user",
                                     "profile not found", "404 not found", "doesn't exist")
                if any(marker in text[:6000] for marker in not_found_markers):
                    self.logger.debug(f"{platform}: 200 but 'not found' markers present")
                    continue
                result.usernames_found.append((platform, str(response.url)))
                self.logger.ok(f"{platform}: {response.url}")
            time.sleep(delay)
        self.logger.info(f"username search complete: {len(result.usernames_found)} "
                         f"of {result.usernames_checked} platforms returned a profile")

    # -- metadata ----------------------------------------------------------- #
    def extract_metadata(self, paths: Sequence[Path], result: OsintResult) -> None:
        """Extract metadata from local files (exiftool or a built-in fallback)."""
        for path in paths:
            if not path.exists():
                result.errors.append(f"metadata source not found: {path}")
                continue
            entry: Dict[str, Any] = {"file": str(path), "size": path.stat().st_size}
            if deps.have("exiftool"):
                code, out, _ = run(["exiftool", "-j", str(path)], timeout=60)
                try:
                    parsed = json.loads(out or "[]")
                    if parsed:
                        entry["exif"] = parsed[0]
                except (ValueError, IndexError):
                    entry["note"] = "exiftool returned unparseable output"
            elif deps.have_module("PIL") and path.suffix.lower() in (
                    ".jpg", ".jpeg", ".png", ".tiff", ".webp"):
                try:
                    from PIL import Image  # type: ignore
                    from PIL.ExifTags import TAGS  # type: ignore
                    with Image.open(path) as image:
                        entry["image"] = {"format": image.format, "size": image.size,
                                          "mode": image.mode}
                        exif = image.getexif()
                        entry["exif"] = {TAGS.get(tag, str(tag)): str(value)
                                         for tag, value in exif.items()}
                        gps = entry["exif"].get("GPSInfo")
                        if gps:
                            entry["warning"] = "GPS coordinates embedded in the image"
                            result.notes.append(f"{path.name} contains GPS EXIF data")
                except Exception as exc:  # noqa: BLE001
                    entry["error"] = str(exc)
            else:
                # Generic fallback: strings + embedded email/URL extraction
                code, out, _ = run(["strings", "-n", "8", str(path)], timeout=60)
                if code == 0:
                    urls = re.findall(r"https?://[^\s\"'<>]{6,120}", out or "")
                    emails = EMAIL_RE.findall(out or "")
                    entry["strings_urls"] = sorted(set(urls))[:25]
                    entry["strings_emails"] = sorted(set(emails))[:25]
                    if emails:
                        result.emails.extend(emails)
                    if not urls and not emails:
                        entry["note"] = "no URLs or emails found in the file body"
            result.metadata.append(entry)
            self.logger.ok(f"metadata extracted from {path.name}")

    # -- orchestration ------------------------------------------------------ #
    def run(self, target: str, output_dir: Path, do_emails: bool = True,
            do_username: bool = False, metadata_paths: Sequence[Path] = ()) -> OsintResult:
        """Run every applicable collector for *target*."""
        result = OsintResult(target=target)
        is_domain = bool(re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", target))
        is_email = "@" in target and bool(EMAIL_RE.fullmatch(target))

        if is_email:
            result.kind = "email"
            result.emails.append(target.lower())
            domain = target.split("@")[1]
            result.notes.append(f"derived domain from email: {domain}")
        elif is_domain:
            result.kind = "domain"
            domain = target
        else:
            result.kind = "username"
            self.search_username(target, result)
            return result

        self.logger.info(f"collecting OSINT for {domain} "
                         f"(engine directory: {output_dir})")
        self.dns_records(domain, result)
        self.whois_lookup(domain, result)
        self.web_fingerprint(domain, result)
        self.crt_sh(domain, result)
        self.subfinder(domain, result)
        if do_emails:
            self.harvester(domain, result, output_dir)
        # Harvest emails from every page we can reach politely
        for url in (result.sitemap_urls[:5] or [f"https://{domain}"]):
            page = self._get(url, timeout=12)
            if page is not None and page.status_code == 200:
                found = EMAIL_RE.findall(page.text)
                result.emails.extend(email for email in found
                                     if not email.lower().endswith((".png", ".jpg", ".gif")))
        result.emails = sorted({email.lower() for email in result.emails})
        result.subdomains = sorted({host.lower() for host in result.subdomains})
        if do_username:
            self.search_username(domain.split(".")[0], result)
        if metadata_paths:
            self.extract_metadata(list(metadata_paths), result)
        return result

    # -- rendering ---------------------------------------------------------- #
    def render(self, result: OsintResult) -> str:
        """Render a colourised console summary."""
        lines = [
            colour(f"  OSINT REPORT  ::  {result.target} ({result.kind})", C.BRIGHT_CYAN),
            f"  generated {result.generated}",
            "",
        ]
        if result.dns_records:
            lines.append(colour("  DNS", C.BOLD))
            for record_type, values in result.dns_records.items():
                joined = ", ".join(values[:4]) + (" ..." if len(values) > 4 else "")
                lines.append(f"    {record_type:<6} {joined}")
            lines.append("")
        if result.whois_summary:
            lines.append(colour("  WHOIS", C.BOLD))
            for line in result.whois_summary.splitlines()[:12]:
                lines.append(f"    {line[:100]}")
            lines.append("")
        if result.http_fingerprint:
            lines.append(colour("  WEB FINGERPRINT", C.BOLD))
            for key, value in result.http_fingerprint.items():
                lines.append(f"    {key:<12} {value}")
            lines.append("")
        if result.subdomains:
            lines.append(colour(f"  SUBDOMAINS ({len(result.subdomains)})", C.BOLD))
            for host in result.subdomains[:30]:
                lines.append(f"    {host}")
            if len(result.subdomains) > 30:
                lines.append(f"    ... and {len(result.subdomains) - 30} more")
            lines.append("")
        if result.emails:
            lines.append(colour(f"  EMAIL ADDRESSES ({len(result.emails)})", C.BOLD))
            for email in result.emails[:30]:
                lines.append(f"    {email}")
            lines.append("")
        if result.usernames_found or result.usernames_checked:
            lines.append(colour(
                f"  USERNAME PRESENCE ({len(result.usernames_found)}/"
                f"{result.usernames_checked})", C.BOLD))
            for platform, url in result.usernames_found:
                lines.append(f"    {platform:<26} {url}")
            lines.append("")
        if result.certificates:
            lines.append(colour("  CERTIFICATE TRANSPARENCY (recent)", C.BOLD))
            for certificate in result.certificates[:8]:
                lines.append(f"    {certificate['common_name'][:44]:<46} "
                             f"{certificate['issuer'][:36]}")
            lines.append("")
        if result.metadata:
            lines.append(colour("  FILE METADATA", C.BOLD))
            for entry in result.metadata:
                lines.append(f"    {entry['file']} ({entry.get('size', 0)} bytes)")
                if entry.get("warning"):
                    lines.append(colour(f"      ⚠ {entry['warning']}", C.BRIGHT_RED))
                exif = entry.get("exif") or {}
                for key in ("Make", "Model", "Software", "DateTimeOriginal", "GPSInfo",
                            "Author", "Creator", "Producer"):
                    if key in exif:
                        lines.append(f"      {key}: {str(exif[key])[:70]}")
            lines.append("")
        if result.robots:
            lines.append(colour("  ROBOTS.TXT (first entries)", C.BOLD))
            for line in result.robots[:10]:
                lines.append(f"    {line[:100]}")
            lines.append("")
        if result.notes:
            lines.append(colour("  NOTES", C.BOLD))
            for note in result.notes:
                lines.append(f"    • {note}")
            lines.append("")
        if result.errors:
            lines.append(colour("  ERRORS / SKIPPED", C.BOLD))
            for error in result.errors:
                lines.append(colour(f"    ✘ {error}", C.YELLOW))
        return "\n".join(lines)

    def write_outputs(self, result: OsintResult, output_dir: Path) -> Dict[str, Path]:
        """Write JSON and markdown reports into *output_dir*."""
        raw_dir = output_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        json_path = write_json(raw_dir / "osint.json", result.as_dict())

        markdown = [f"# OSINT report: {result.target}", ""]
        markdown.append(f"- **Type**: {result.kind}")
        markdown.append(f"- **Generated**: {result.generated}")
        markdown.append(f"- **Operator**: {self.config.get('general.operator_name', 'operator')}")
        markdown.append("")
        if result.dns_records:
            markdown.append("## DNS records\n")
            for record_type, values in result.dns_records.items():
                markdown.append(f"- **{record_type}**: {', '.join(values)}")
            markdown.append("")
        if result.whois_summary:
            markdown.append("## WHOIS\n\n```\n" + result.whois_summary + "\n```\n")
        if result.http_fingerprint:
            markdown.append("## Web fingerprint\n")
            for key, value in result.http_fingerprint.items():
                markdown.append(f"- **{key}**: {value}")
            markdown.append("")
        if result.subdomains:
            markdown.append(f"## Subdomains ({len(result.subdomains)})\n\n```\n")
            markdown.extend(result.subdomains)
            markdown.append("```\n")
        if result.emails:
            markdown.append(f"## Email addresses ({len(result.emails)})\n\n```\n")
            markdown.extend(result.emails)
            markdown.append("```\n")
        if result.usernames_found:
            markdown.append("## Username presence\n\n| Platform | URL |\n|---|---|\n")
            for platform, url in result.usernames_found:
                markdown.append(f"| {platform} | {url} |")
            markdown.append("")
        if result.metadata:
            markdown.append("## File metadata\n")
            for entry in result.metadata:
                markdown.append(f"### {entry['file']}\n")
                if entry.get("warning"):
                    markdown.append(f"> ⚠ {entry['warning']}\n")
                markdown.append("```json")
                markdown.append(json.dumps(entry, indent=2)[:4000])
                markdown.append("```\n")
        if result.notes:
            markdown.append("## Analyst notes\n")
            for note in result.notes:
                markdown.append(f"- {note}")
            markdown.append("")
        if result.errors:
            markdown.append("## Skipped or failed collectors\n")
            for error in result.errors:
                markdown.append(f"- {error}")
            markdown.append("")
        markdown.append("---")
        markdown.append(f"Generated by cyberdeck-arsenal v{__version__}. "
                        f"OSINT must only be collected for lawful purposes; respect platform "
                        f"terms of service and applicable privacy law.")
        markdown_path = output_dir / "OSINT.md"
        markdown_path.write_text("\n".join(markdown) + "\n")
        return {"json": json_path, "markdown": markdown_path}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="osint_gatherer.py",
        description="OSINT collection: emails, domains, usernames and file metadata",
        epilog="Also available as: cdeck osint")
    parser.add_argument("target", nargs="?", default=None,
                        help="domain, email address or username")
    parser.add_argument("--domain", default=None, help="domain to investigate")
    parser.add_argument("--username", default=None, help="username to check across platforms")
    parser.add_argument("--email", default=None, help="email address to investigate")
    parser.add_argument("--metadata", action="append", default=[],
                        help="file to analyse for metadata (repeatable)")
    parser.add_argument("--emails", action="store_true", default=True,
                        help="harvest email addresses (default on)")
    parser.add_argument("--no-emails", action="store_true", help="skip email harvesting")
    parser.add_argument("--output", default=None, help="output directory")
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress the console report")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    parser.add_argument("--version", action="version", version=f"osint_gatherer {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("osint_gatherer", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)), quiet=args.quiet)

    target = args.domain or args.username or args.email or args.target
    if not target and not args.metadata:
        logger.error("nothing to do: pass a domain, username, email address or --metadata file")
        print("  usage: osint_gatherer.py example.com")
        print("         osint_gatherer.py --username jsmith")
        print("         osint_gatherer.py --metadata ~/Downloads/report.pdf")
        return 2

    metadata_paths = [Path(p).expanduser() for p in args.metadata]

    if target and not (deps.have("dig") or deps.have("whois")):
        logger.warn("dig and whois are missing - install bind-tools and whois for full coverage")

    gatherer = OsintGatherer(config, logger, timeout=args.timeout)

    output_dir = Path(args.output).expanduser() if args.output else engagement_dir(
        target or (metadata_paths[0].stem if metadata_paths else "files"))

    try:
        if target:
            logger.info(f"target: {target}")
            result = gatherer.run(target, output_dir,
                                  do_emails=not args.no_emails,
                                  do_username=bool(args.username),
                                  metadata_paths=metadata_paths)
        else:
            result = OsintResult(target=str(metadata_paths[0]), kind="files")
            gatherer.extract_metadata(metadata_paths, result)

        paths = gatherer.write_outputs(result, output_dir)

        if args.json:
            print(json.dumps(result.as_dict(), indent=2, default=str))
        elif not args.quiet:
            print(gatherer.render(result))
            logger.ok(f"reports written: {paths['markdown']} and {paths['json']}")
        else:
            logger.ok(f"reports written: {paths['markdown']} and {paths['json']}")

        # Record in the shared event log
        try:
            with Database("events", logger=logger) as db:
                db.event("osint_gatherer", "osint",
                         f"OSINT collected for {result.target}: {len(result.emails)} email(s), "
                         f"{len(result.subdomains)} subdomain(s)",
                         "INFO", {"target": result.target, "kind": result.kind})
        except Exception:  # noqa: BLE001
            pass
        return 0
    except KeyboardInterrupt:
        logger.warn("interrupted by operator")
        return 130


if __name__ == "__main__":
    sys.exit(main())
