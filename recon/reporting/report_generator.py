#!/usr/bin/env python3
"""
report_generator.py - engagement report builder
==============================================

Description
-----------
Reads everything produced during an engagement (nmap XML/gnmap, nikto, nuclei,
whatweb, gobuster/ffuf, theHarvester output, OSINT JSON, the cyberdeck SQLite
databases) and produces client-ready deliverables:

    * markdown report     - full technical write-up
    * HTML report         - self-contained, styled, printable to PDF
    * executive summary   - one page, no jargon, for decision makers
    * findings CSV        - importable into a tracker or spreadsheet
    * JSON bundle         - everything machine-readable

Findings are rated with a simple, defensible model: severity is derived from
the evidence (exposed services, vulnerability scanner hits, missing hardening),
each finding carries a remediation paragraph, and an overall risk rating is
computed from the highest severity present.

Templates live in ``data/templates/`` and can be edited by the operator.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; stdlib only otherwise (html templating is hand-rolled)
Licence     : MIT - authorised use only, see docs/LEGAL.md

Usage
-----
    cdeck report /opt/cyberdeck-arsenal/reports/example.com_2026-10-16_120000
    python3 recon/reporting/report_generator.py <dir> --formats md,html,exec,csv
    python3 recon/reporting/report_generator.py <dir> --client "Acme Ltd" --scope "External"
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
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
        C, Config, Logger, colour, deps, human_duration, now_iso, read_json,
    )
except ImportError as exc:
    print(f"report_generator: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

#: Severity ordering used throughout the report
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

#: Remediation advice keyed on a matched pattern in the finding title
REMEDIATION_LIBRARY: Tuple[Tuple[str, str], ...] = (
    ("anonymous ftp", "Disable anonymous authentication on the FTP service and require "
     "authenticated, encrypted transfers (SFTP/FTPS). If FTP is no longer required, "
     "remove the service."),
    ("smb", "Disable SMBv1, require SMB signing, restrict share permissions to the minimum "
     "required principals and block ports 139/445 at the network boundary."),
    ("rdp", "Restrict RDP to a management network or VPN, enable Network Level "
     "Authentication and enforce multi-factor authentication for all remote sessions."),
    ("telnet", "Replace Telnet with SSH. Telnet transmits credentials and session data in "
     "cleartext and should be disabled on every device that supports an alternative."),
    ("mysql", "Bind the database to localhost or a management interface, remove default and "
     "test accounts, and require strong credentials."),
    ("postgres", "Restrict database listeners to trusted networks, disable trust "
     "authentication and rotate default credentials."),
    ("redis", "Enable authentication, bind Redis to a private interface and disable the "
     "CONFIG and DEBUG commands in production."),
    ("mongodb", "Enable authentication and authorisation, and bind MongoDB to an internal "
     "interface only."),
    ("elasticsearch", "Enable security features, require authentication and place "
     "Elasticsearch behind an authenticated reverse proxy."),
    ("tls", "Disable protocols below TLS 1.2, remove weak ciphers, enable HSTS with a long "
     "max-age, and automate certificate renewal."),
    ("ssl", "Disable protocols below TLS 1.2, remove weak ciphers and automate certificate "
     "renewal to prevent expiry."),
    ("expired", "Automate certificate renewal (for example with certbot or ACME) and "
     "monitor expiry with an alert at 30 days."),
    ("security header", "Add the missing security headers at the web server or reverse "
     "proxy: HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, "
     "Referrer-Policy and Permissions-Policy."),
    ("waf", "Review WAF rule coverage and tune it; ensure it is not the only compensating "
     "control for known application weaknesses."),
    ("wordpress", "Keep WordPress core, themes and plugins patched, remove unused plugins, "
     "enforce strong administrator credentials and enable multi-factor authentication."),
    ("wp-login", "Restrict /wp-login.php by IP or add rate limiting and multi-factor "
     "authentication; consider a maintenance-mode plugin to hide the login endpoint."),
    ("directory listing", "Disable directory listing in the web server configuration."),
    ("exposed", "Restrict the exposed service to the minimum set of source addresses and "
     "require authentication in front of it."),
    ("cve-", "Apply the vendor patch for the referenced CVE, or apply the documented "
     "compensating control until patching is possible."),
    ("vulnerable", "Patch the affected software to a supported version and re-test."),
    ("arp", "Enable Dynamic ARP Inspection or similar protection on the switching fabric, "
     "and use encrypted protocols to protect credentials."),
    ("spoof", "Investigate the L2 environment: enable DHCP snooping and Dynamic ARP "
     "Inspection, and confirm no unauthorised devices are bridging the network."),
    ("rogue", "Locate and disconnect the rogue access point, then change any credentials "
     "that may have been captured. Enable WIPS or regular RF sweeps to detect reoccurrence."),
    ("weak", "Replace weak or default credentials with unique, strong passwords stored in a "
     "password manager; enable multi-factor authentication."),
    ("default credential", "Change every default credential before deployment and add a "
     "configuration check to the build pipeline."),
    ("open", "Close the port if it is not required, or restrict it to the trusted management "
     "network."),
)


@dataclass
class Finding:
    """A single reportable finding."""

    title: str
    severity: str = "INFO"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    category: str = "general"
    host: str = ""
    port: str = ""
    references: List[str] = field(default_factory=list)
    source: str = ""

    @property
    def severity_rank(self) -> int:
        """Numeric severity for sorting and risk calculation."""
        return SEVERITY_ORDER.get(self.severity.upper(), 0)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for JSON/CSV output."""
        return {
            "title": self.title, "severity": self.severity, "category": self.category,
            "host": self.host, "port": self.port, "description": self.description,
            "evidence": self.evidence, "remediation": self.remediation,
            "references": self.references, "source": self.source,
        }

    def suggest_remediation(self) -> str:
        """Return remediation text, inferring it from the title when absent."""
        if self.remediation:
            return self.remediation
        haystack = f"{self.title} {self.description}".lower()
        for needle, advice in REMEDIATION_LIBRARY:
            if needle in haystack:
                return advice
        return ("Review the service configuration against the relevant hardening baseline "
                "(for example CIS Benchmarks or the vendor's security guide) and close the "
                "exposure, then re-test to confirm.")


@dataclass
class Evidence:
    """An artefact produced during the engagement."""

    path: str
    size: int
    kind: str = "file"
    sha256: str = ""


class ReportData:
    """Collects findings, hosts, artefacts and metadata for the report."""

    def __init__(self, directory: Path, logger: Logger) -> None:
        """Scan *directory* and load everything we can parse."""
        self.directory = Path(directory)
        self.logger = logger
        self.findings: List[Finding] = []
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.artefacts: List[Evidence] = []
        self.summaries: List[Tuple[str, str]] = []
        self.osint: Dict[str, Any] = {}
        self.scan_commands: List[str] = []
        self.errors: List[str] = []
        self.timeline: List[Tuple[str, str]] = []

    # -- collection --------------------------------------------------------- #
    def collect(self) -> None:
        """Walk the engagement directory and parse every recognised artefact."""
        if not self.directory.is_dir():
            self.errors.append(f"directory not found: {self.directory}")
            return
        for path in sorted(self.directory.rglob("*")):
            if not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            self.artefacts.append(Evidence(path=str(path.relative_to(self.directory)),
                                           size=size,
                                           kind=path.suffix.lstrip(".") or "file"))
            try:
                self.timeline.append((datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                                      str(path.relative_to(self.directory))))
            except OSError:
                continue
            suffix = path.suffix.lower()
            name = path.name.lower()
            if suffix == ".xml" and "nmap" in name:
                self._parse_nmap_xml(path)
            elif suffix == ".gnmap" or name.endswith(".nmap"):
                self._parse_nmap_text(path)
            elif suffix == ".json":
                self._parse_json(path)
            elif suffix in (".md", ".txt", ".html") and "report" not in name:
                self._parse_text(path, name)
        self.findings.sort(key=lambda finding: -finding.severity_rank)
        self.timeline.sort()

    def _parse_nmap_xml(self, path: Path) -> None:
        """Extract hosts, services and script findings from nmap XML."""
        try:
            tree = ET.parse(path)
        except ET.ParseError as exc:
            self.errors.append(f"nmap XML parse failed for {path.name}: {exc}")
            return
        root = tree.getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            address_element = host.find("address")
            address = address_element.get("addr") if address_element is not None else "unknown"
            hostname_element = host.find("hostnames/hostname")
            hostname = hostname_element.get("name") if hostname_element is not None else ""
            entry = self.hosts.setdefault(address, {
                "ip": address, "hostname": hostname, "os": "", "ports": []})
            if hostname and not entry["hostname"]:
                entry["hostname"] = hostname
            for osmatch in host.findall("os/osmatch"):
                entry["os"] = osmatch.get("name", entry["os"])
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                banner = " ".join(part for part in (product, version) if part).strip()
                entry["ports"].append({
                    "port": port.get("portid"), "protocol": port.get("protocol"),
                    "service": service_name, "version": banner,
                    "state": state.get("state"),
                })
                self._service_finding(address, port.get("portid", ""), service_name,
                                      banner, service)
                # Script output: the highest-signal part of an nmap scan
                for script in port.findall("script"):
                    output = script.get("output", "")
                    script_id = script.get("id", "script")
                    if re.search(r"VULNERABLE|CVE-\d{4}-\d{4,}", output, re.IGNORECASE):
                        self.findings.append(Finding(
                            title=f"{script_id} reported a vulnerability on "
                                  f"{address}:{port.get('portid')}",
                            severity="HIGH", category="vulnerability",
                            host=address, port=port.get("portid", ""),
                            description=f"The nmap script '{script_id}' produced output "
                                        f"indicating a known vulnerability.",
                            evidence=output.strip()[:1200],
                            source=f"nmap ({path.name})"))
            for script in host.findall("hostscript/script"):
                output = script.get("output", "")
                if re.search(r"VULNERABLE|CVE-\d{4}-\d{4,}", output, re.IGNORECASE):
                    self.findings.append(Finding(
                        title=f"Host script {script.get('id')} reported a vulnerability "
                              f"on {address}",
                        severity="HIGH", category="vulnerability", host=address,
                        evidence=output.strip()[:1200], source=f"nmap ({path.name})"))

    def _service_finding(self, host: str, port: str, service: str, banner: str,
                         service_element: Any) -> None:
        """Raise findings for individually risky services."""
        risky = {
            "telnet": ("HIGH", "Cleartext remote administration (Telnet) is exposed"),
            "ftp": ("MEDIUM", "FTP service is exposed"),
            "ftp-data": ("LOW", "FTP data channel is exposed"),
            "msrpc": ("MEDIUM", "MSRPC endpoint mapper is exposed"),
            "netbios-ssn": ("MEDIUM", "NetBIOS session service is exposed"),
            "microsoft-ds": ("HIGH", "SMB file sharing is exposed"),
            "rdp": ("HIGH", "Remote Desktop is exposed"),
            "ms-wbt-server": ("HIGH", "Remote Desktop is exposed"),
            "vnc": ("HIGH", "VNC remote desktop is exposed"),
            "mysql": ("MEDIUM", "MySQL database is exposed"),
            "postgresql": ("MEDIUM", "PostgreSQL database is exposed"),
            "redis": ("HIGH", "Redis is exposed (often unauthenticated)"),
            "mongodb": ("HIGH", "MongoDB is exposed"),
            "elasticsearch": ("HIGH", "Elasticsearch is exposed"),
            "memcache": ("MEDIUM", "Memcached is exposed"),
            "docker": ("HIGH", "Docker API is exposed (equivalent to root on the host)"),
            "rlogin": ("HIGH", "rlogin is exposed"),
            "exec": ("HIGH", "rexec is exposed"),
            "snmp": ("MEDIUM", "SNMP is exposed - check for default community strings"),
            "ipp": ("LOW", "Print service is exposed"),
            "smtp": ("LOW", "SMTP service is exposed - verify it is not an open relay"),
            "kerberos-sec": ("LOW", "Kerberos service is exposed"),
        }
        if service in risky:
            severity, title = risky[service]
            self.findings.append(Finding(
                title=f"{title} ({host}:{port})",
                severity=severity, category="exposed-service", host=host, port=port,
                description=f"Port {port}/{service} is open. Banner: {banner or 'not disclosed'}.",
                evidence=f"nmap reported {service} open on {host}:{port}"
                         + (f" ({banner})" if banner else ""),
                source="nmap"))
        # Anonymous FTP is specifically called out by nmap's ftp-anon script
        if service_element is not None:
            for script in getattr(service_element, "findall", lambda *_: [])("script"):
                if script.get("id") == "ftp-anon":
                    self.findings.append(Finding(
                        title=f"Anonymous FTP access is enabled on {host}:{port}",
                        severity="HIGH", category="misconfiguration", host=host, port=port,
                        evidence=script.get("output", "")[:600],
                        source="nmap"))

    def _parse_nmap_text(self, path: Path) -> None:
        """Parse nmap .nmap/.gnmap output for services and notable script lines."""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for match in re.finditer(r"^(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)$", text, re.MULTILINE):
            port, protocol, service, banner = match.groups()
            host_match = re.findall(r"Nmap scan report for (?:(\S+) \()?([\d.a-fA-F:]+)\)?", text)
            host = host_match[-1][1] if host_match else "unknown"
            self.hosts.setdefault(host, {"ip": host, "hostname": "", "os": "", "ports": []})
            self._service_finding(host, port, service, banner.strip(), None)
        if re.search(r"SSH-2.0-OpenSSH_[1-6]\.", text):
            self.findings.append(Finding(
                title="Outdated OpenSSH version detected",
                severity="MEDIUM", category="patching",
                evidence="An OpenSSH version below 7.x was observed in the service banner.",
                source=f"nmap ({path.name})"))
        for line in text.splitlines():
            if "Anonymous FTP" in line or "ftp-anon" in line.lower():
                self.findings.append(Finding(
                    title="Anonymous FTP access detected",
                    severity="HIGH", category="misconfiguration",
                    evidence=line.strip()[:400], source=path.name))

    def _parse_json(self, path: Path) -> None:
        """Parse OSINT exports, nuclei JSON and ffuf results."""
        data = read_json(path)
        if not data:
            return
        name = path.name.lower()
        if isinstance(data, dict) and "emails" in data and "subdomains" in data:
            self.osint = data
            self.findings.append(Finding(
                title=f"{len(data.get('emails', []))} email address(es) and "
                      f"{len(data.get('subdomains', []))} subdomain(s) disclosed publicly",
                severity="LOW" if len(data.get("emails", [])) < 5 else "MEDIUM",
                category="information-disclosure",
                description="Public sources (certificate transparency, search engines, "
                            "website content) reveal internal naming and staff addresses, "
                            "which are directly usable in phishing and password spraying.",
                evidence=", ".join(data.get("emails", [])[:12])
                         + ("; " + ", ".join(data.get("subdomains", [])[:12])
                            if data.get("subdomains") else ""),
                source=f"osint ({path.name})"))
        elif isinstance(data, dict) and "results" in data and name.startswith("ffuf"):
            for result in data.get("results", [])[:50]:
                self.findings.append(Finding(
                    title=f"Discoverable path: {result.get('url', '?')}",
                    severity="LOW", category="content-discovery",
                    evidence=f"HTTP {result.get('status')} - {result.get('length')} bytes",
                    source=f"ffuf ({path.name})"))
        elif isinstance(data, list):
            for item in data[:50]:
                if isinstance(item, dict) and "info" in item:  # nuclei JSON lines
                    info = item.get("info", {})
                    severity = str(info.get("severity", "info")).upper()
                    self.findings.append(Finding(
                        title=f"{info.get('name', 'nuclei finding')} on "
                              f"{item.get('matched-at', '?')}",
                        severity=severity if severity in SEVERITY_ORDER else "INFO",
                        category="vulnerability",
                        description=str(info.get("description", ""))[:400],
                        evidence=json.dumps(item)[:800],
                        references=[str(info.get("reference", ""))[:200]] if
                        info.get("reference") else [],
                        source=f"nuclei ({path.name})"))

    def _parse_text(self, path: Path, name: str) -> None:
        """Parse nikto, whatweb, gobuster, sslscan and per-tool summaries."""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        if "nikto" in name:
            for line in text.splitlines():
                if line.startswith("+"):  # nikto findings are prefixed with '+'
                    body = line[1:].strip()
                    if not body or body.startswith("Target") or body.startswith("Server:"):
                        continue
                    severity = "HIGH" if re.search(r"OSVDB-\d|CVE-\d{4}-\d{4,}", body) \
                        else "MEDIUM"
                    self.findings.append(Finding(
                        title=f"Nikto: {body[:110]}",
                        severity=severity, category="web",
                        evidence=body[:600], source=f"nikto ({path.name})"))
        elif "gobuster" in name or "dirb" in name:
            for line in text.splitlines():
                if "Status: 200" in line or re.match(r"^\+?/", line.strip()):
                    self.findings.append(Finding(
                        title=f"Path discovered: {line.split()[0][:90]}",
                        severity="LOW", category="content-discovery",
                        evidence=line.strip()[:300], source=path.name))
        elif "sslscan" in name:
            for line in text.splitlines():
                if re.search(r"SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|\b40 bits\b|\b56 bits\b|RC4|3DES", line):
                    self.findings.append(Finding(
                        title=f"Legacy TLS configuration: {line.strip()[:80]}",
                        severity="MEDIUM", category="crypto",
                        evidence=line.strip()[:300], source="sslscan"))
        elif "harvester" in name:
            emails = set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text))
            if emails:
                self.findings.append(Finding(
                    title=f"{len(emails)} email address(es) discovered for the target",
                    severity="LOW", category="information-disclosure",
                    evidence=", ".join(sorted(emails)[:15]), source=path.name))
        elif "security_headers" in name:
            for line in text.splitlines():
                if line.strip() and "===" not in line and "missing" not in line.lower():
                    self.findings.append(Finding(
                        title=f"Missing HTTP security header: {line.strip()}",
                        severity="LOW", category="web-hardening",
                        evidence=f"{line.strip()} was absent from the HTTP response headers",
                        source="security header audit"))
        elif "reachability" in name or "headers" in name:
            for match in re.finditer(r"^Server: (.+)$", text, re.MULTILINE | re.IGNORECASE):
                server = match.group(1).strip()
                if re.search(r"\d+\.\d+", server):
                    self.findings.append(Finding(
                        title=f"Server banner discloses version information: {server}",
                        severity="LOW", category="information-disclosure",
                        evidence=f"HTTP header: Server: {server}", source=path.name))
        for match in re.finditer(r"^(-{2,}|#)\s*(.+)$", text, re.MULTILINE):
            if len(self.summaries) < 25 and len(match.group(2)) < 120:
                self.summaries.append((path.name, match.group(2)))

    # -- derived data -------------------------------------------------------- #
    def overall_risk(self) -> str:
        """Compute the overall engagement risk rating."""
        if not self.findings:
            return "Informational"
        highest = max(finding.severity_rank for finding in self.findings)
        return {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}[highest]

    def counts_by_severity(self) -> Dict[str, int]:
        """Return finding counts per severity."""
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity.upper()] = counts.get(finding.severity.upper(), 0) + 1
        return counts

    def open_port_count(self) -> int:
        """Total number of open ports across all hosts."""
        return sum(len(host.get("ports", [])) for host in self.hosts.values())


class ReportBuilder:
    """Renders ReportData into the requested output formats."""

    def __init__(self, data: ReportData, config: Config, logger: Logger,
                 client: str = "", scope: str = "Internal network / web application",
                 tester: str = "") -> None:
        """Store report metadata."""
        self.data = data
        self.config = config
        self.logger = logger
        self.client = client or "Internal engagement"
        self.scope = scope
        self.tester = tester or str(config.get("general.operator_name", "cyberdeck operator"))
        self.generated = now_iso()
        self.templates_dir = self._find_templates()

    def _find_templates(self) -> Path:
        """Locate the template directory (install dir first, then the repo)."""
        install = Path(self.config.get("general.install_dir", "/opt/cyberdeck-arsenal"))
        candidates = [install / "data" / "templates",
                      Path(__file__).resolve().parent.parent.parent / "data" / "templates"]
        for candidate in candidates:
            if candidate.is_dir():
                return candidate
        return candidates[-1]

    # -- markdown ----------------------------------------------------------- #
    def _template_header_footer(self) -> Tuple[List[str], List[str]]:
        """Load the markdown template (``data/templates/report_template.md``).

        The template is split on the ``<!-- BODY -->`` marker: everything above
        becomes the report header, everything below the footer. ``{{TOKEN}}``
        placeholders are substituted so operators can customise the front matter
        of every report without touching the code.
        """
        path = self.templates_dir / "report_template.md"
        if not path.is_file():
            return [], []
        try:
            template = path.read_text()
        except OSError:
            return [], []
        if "<!-- BODY -->" not in template:
            return [], []
        header, _, footer = template.partition("<!-- BODY -->")
        # Strip documentation comments from the top of the template so they do
        # not end up in the delivered report.
        while True:
            stripped = header.lstrip()
            if stripped.startswith("<!--"):
                end = stripped.find("-->")
                if end == -1:
                    break
                header = stripped[end + 3:]
            else:
                header = stripped
                break
        values = {
            "CLIENT": self.client, "GENERATED": self.generated, "TESTER": self.tester,
            "SCOPE": self.scope, "VERSION": __version__,
            "RISK": self.data.overall_risk(),
        }
        for token, value in values.items():
            header = header.replace("{{%s}}" % token, value)
            footer = footer.replace("{{%s}}" % token, value)
        return (header.strip("\n").split("\n"),
                footer.strip("\n").split("\n"))

    def render_markdown(self) -> str:
        """Render the full markdown report (template aware)."""
        data = self.data
        counts = data.counts_by_severity()
        template_header, template_footer = self._template_header_footer()
        lines: List[str] = list(template_header)
        if lines:
            lines.append("")
        lines.append(f"# Security assessment report: {self.client}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| **Client / owner** | {self.client} |")
        lines.append(f"| **Scope** | {self.scope} |")
        lines.append(f"| **Assessment date** | {self.generated} |")
        lines.append(f"| **Tester** | {self.tester} |")
        lines.append(f"| **Overall risk rating** | **{data.overall_risk()}** |")
        lines.append(f"| **Findings** | {len(data.findings)} "
                     f"(critical {counts.get('CRITICAL', 0)}, high {counts.get('HIGH', 0)}, "
                     f"medium {counts.get('MEDIUM', 0)}, low {counts.get('LOW', 0)}) |")
        lines.append(f"| **Hosts in scope observed** | {len(data.hosts)} |")
        lines.append(f"| **Open ports observed** | {data.open_port_count()} |")
        lines.append(f"| **Evidence artefacts** | {len(data.artefacts)} |")
        lines.append("")
        lines.append("> This report was produced with cyberdeck-arsenal. Testing was performed "
                     "only against assets the client confirmed they own or are authorised to "
                     "test, and only within the agreed scope and time window.")
        lines.append("")

        lines.append("## Executive summary")
        lines.append("")
        lines.append(self._executive_paragraph())
        lines.append("")

        lines.append("## Scope and methodology")
        lines.append("")
        lines.append(f"- **Scope**: {self.scope}")
        lines.append("- **Approach**: reconnaissance (passive then active), service "
                     "enumeration, targeted vulnerability checks, and manual verification of "
                     "high-severity results.")
        lines.append("- **Principles**: no denial-of-service testing, no destructive payloads, "
                     "no data exfiltration beyond proof of exposure.")
        lines.append("")
        if data.scan_commands:
            lines.append("Commands executed:")
            lines.append("")
            lines.append("```")
            lines.extend(data.scan_commands)
            lines.append("```")
            lines.append("")

        lines.append("## Findings summary")
        lines.append("")
        lines.append("| # | Severity | Finding | Host | Category |")
        lines.append("|---|---|---|---|---|")
        for index, finding in enumerate(data.findings, start=1):
            lines.append(f"| {index} | {finding.severity} | {finding.title[:90]} | "
                         f"{finding.host or '-'} | {finding.category} |")
        if not data.findings:
            lines.append("| - | - | No findings were identified | - | - |")
        lines.append("")

        lines.append("## Detailed findings")
        lines.append("")
        if not data.findings:
            lines.append("No findings were identified during this assessment. The absence of "
                         "findings is not proof of security; it reflects the depth and scope "
                         "of the testing performed.")
            lines.append("")
        for index, finding in enumerate(data.findings, start=1):
            lines.append(f"### {index}. {finding.title}")
            lines.append("")
            lines.append(f"- **Severity**: {finding.severity}")
            lines.append(f"- **Category**: {finding.category}")
            if finding.host:
                lines.append(f"- **Host**: {finding.host}"
                             + (f":{finding.port}" if finding.port else ""))
            if finding.source:
                lines.append(f"- **Source**: {finding.source}")
            lines.append("")
            if finding.description:
                lines.append("**Description**")
                lines.append("")
                lines.append(finding.description)
                lines.append("")
            lines.append("**Evidence**")
            lines.append("")
            lines.append("```")
            lines.append((finding.evidence or "See the raw artefacts listed in the appendix.")
                         .replace("```", "'''"))
            lines.append("```")
            lines.append("")
            lines.append("**Remediation**")
            lines.append("")
            lines.append(finding.suggest_remediation())
            lines.append("")
            if finding.references:
                lines.append("**References**")
                lines.append("")
                for reference in finding.references:
                    if reference:
                        lines.append(f"- {reference}")
                lines.append("")

        lines.append("## Host inventory")
        lines.append("")
        if data.hosts:
            lines.append("| Host | Name | OS guess | Open ports |")
            lines.append("|---|---|---|---|")
            for host in sorted(data.hosts.values(), key=lambda entry: entry["ip"]):
                ports = ", ".join(
                    f"{port['port']}/{port['service']}"
                    + (f" ({port['version'][:24]})" if port.get("version") else "")
                    for port in sorted(host.get("ports", []),
                                       key=lambda port: int(port["port"] or 0)))
                lines.append(f"| {host['ip']} | {host['hostname'] or '-'} | "
                             f"{host['os'] or 'unknown'} | {ports or '-'} |")
        else:
            lines.append("No host inventory was captured (no port scan stage completed).")
        lines.append("")

        if data.osint:
            lines.append("## Public information exposure (OSINT)")
            lines.append("")
            emails = data.osint.get("emails", [])
            subdomains = data.osint.get("subdomains", [])
            if emails:
                lines.append(f"- **Email addresses ({len(emails)})**: "
                             + ", ".join(f"`{email}`" for email in emails[:20]))
            if subdomains:
                lines.append(f"- **Subdomains ({len(subdomains)})**: "
                             + ", ".join(f"`{host}`" for host in subdomains[:20]))
            for note in data.osint.get("notes", [])[:10]:
                lines.append(f"- {note}")
            lines.append("")

        lines.append("## Timeline")
        lines.append("")
        lines.append("| Timestamp | Artefact |")
        lines.append("|---|---|")
        for timestamp, artefact in data.timeline[:120]:
            lines.append(f"| {timestamp} | `{artefact}` |")
        lines.append("")

        lines.append("## Appendix A - artefacts and integrity")
        lines.append("")
        lines.append("| Artefact | Size (bytes) | SHA-256 |")
        lines.append("|---|---|---|")
        for artefact in data.artefacts[:200]:
            lines.append(f"| `{artefact.path}` | {artefact.size} | "
                         f"{artefact.sha256[:32] + '...' if artefact.sha256 else 'pending'} |")
        lines.append("")
        lines.append("Run `cdeck hash <directory> --verify` to confirm the integrity of these "
                     "artefacts against the chain-of-custody log.")
        lines.append("")

        lines.append("## Appendix B - remediation priority")
        lines.append("")
        priority = [finding for finding in data.findings if finding.severity_rank >= 3]
        if priority:
            lines.append("| Priority | Action |")
            lines.append("|---|---|")
            for index, finding in enumerate(priority[:25], start=1):
                lines.append(f"| {index} | {finding.suggest_remediation()[:180]} |")
        else:
            lines.append("No critical or high severity findings required immediate action. "
                         "Address medium and low findings through normal change control.")
        lines.append("")

        if data.errors:
            lines.append("## Appendix C - collection notes")
            lines.append("")
            for error in data.errors[:40]:
                lines.append(f"- {error}")
            lines.append("")

        lines.append("---")
        lines.append("")
        if template_footer:
            lines.extend(template_footer)
            lines.append("")
        lines.append(f"Report generated by cyberdeck-arsenal v{__version__} on {self.generated}. "
                     f"Findings reflect the state of the systems at the time of testing and "
                     f"should be re-validated after remediation.")
        return "\n".join(lines)

    def _executive_paragraph(self) -> str:
        """Return a short, non-technical summary paragraph."""
        data = self.data
        counts = data.counts_by_severity()
        critical, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)
        medium, low = counts.get("MEDIUM", 0), counts.get("LOW", 0)
        sentences = [
            f"A security assessment of {self.client} was carried out on {self.generated[:10]}, "
            f"covering {self.scope.lower()}."
        ]
        if critical or high:
            sentences.append(
                f"The assessment identified {critical + high} high-impact issue(s) that should "
                f"be addressed immediately: these represent realistic paths for an attacker to "
                f"access systems or data.")
        elif medium:
            sentences.append(
                f"No critical issues were found, but {medium} medium-severity issue(s) weaken "
                f"the security posture and should be fixed within normal change cycles.")
        elif low:
            sentences.append(
                f"No critical or high severity issues were identified. {low} low-severity "
                f"finding(s) relate to hardening and information disclosure.")
        else:
            sentences.append("No findings were identified within the scope tested.")
        sentences.append(
            f"In total {len(data.findings)} finding(s) were recorded across "
            f"{len(data.hosts)} host(s) and {data.open_port_count()} open network service(s).")
        sentences.append(
            "The detailed sections below list each finding with evidence and a specific "
            "remediation step; the appendix records the artefacts collected and their hashes "
            "so the results can be reproduced and verified.")
        return " ".join(sentences)

    # -- HTML --------------------------------------------------------------- #
    #: Built-in HTML template. Tokens in double braces are substituted verbatim
    #: (no str.format), so CSS braces and JavaScript are safe inside a template.
    HTML_TEMPLATE_FALLBACK = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security assessment report - {{CLIENT}}</title>
<style>
 :root { --bg:#0e1116; --panel:#151b23; --ink:#d7e3ee; --dim:#7d8b99;
         --accent:#00ffd5; --critical:#ff4d4d; --high:#ff9640; --medium:#ffd166;
         --low:#5cc8ff; --info:#8d9aa6; }
 * { box-sizing:border-box; }
 body { margin:0; background:var(--bg); color:var(--ink);
        font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
 .wrap { max-width:1000px; margin:0 auto; padding:40px 24px 80px; }
 h1 { font-size:2rem; margin:0 0 4px; color:#fff; }
 h2 { margin-top:2.4rem; padding-bottom:.4rem; border-bottom:1px solid #263042; color:var(--accent); }
 h3 { margin-top:2rem; color:#fff; }
 .sub { color:var(--dim); margin-bottom:2rem; }
 .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:24px 0; }
 .card { background:var(--panel); border:1px solid #263042; border-radius:10px; padding:14px 16px; }
 .card .label { color:var(--dim); font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; }
 .card .value { font-size:1.35rem; font-weight:600; }
 table { width:100%; border-collapse:collapse; margin:16px 0; font-size:.92rem; }
 th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #263042; vertical-align:top; }
 th { color:var(--dim); text-transform:uppercase; font-size:.75rem; letter-spacing:.05em; }
 code, pre { background:#0b0f14; border:1px solid #263042; border-radius:6px;
             font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.86rem; }
 code { padding:2px 5px; }
 pre { padding:12px; overflow-x:auto; white-space:pre-wrap; }
 .severity { display:inline-block; padding:2px 9px; border-radius:999px; font-size:.74rem;
             font-weight:700; letter-spacing:.04em; color:#0e1116; }
 .CRITICAL { background:var(--critical); } .HIGH { background:var(--high); }
 .MEDIUM { background:var(--medium); } .LOW { background:var(--low); }
 .INFO { background:var(--info); }
 .finding { background:var(--panel); border:1px solid #263042; border-left:4px solid var(--dim);
            border-radius:10px; padding:18px 20px; margin:18px 0; }
 .finding.CRITICAL { border-left-color:var(--critical); }
 .finding.HIGH { border-left-color:var(--high); }
 .finding.MEDIUM { border-left-color:var(--medium); }
 .finding.LOW { border-left-color:var(--low); }
 .meta { color:var(--dim); font-size:.85rem; margin:6px 0 12px; }
 .label { color:var(--accent); font-weight:600; display:block; margin:14px 0 4px; }
 a { color:var(--accent); }
 footer { margin-top:60px; color:var(--dim); font-size:.85rem; border-top:1px solid #263042; padding-top:16px; }
 @media print { body { background:#fff; color:#111; } .card,.finding,pre,code { background:#f7f8fa; }
   h2 { color:#0b5; } .wrap { padding:0; } .severity { color:#000; } }
</style></head><body><div class="wrap">
<h1>Security assessment report</h1>
<div class="sub">{{CLIENT}} &middot; {{GENERATED}} &middot; overall risk {{RISK}} &middot; prepared by {{TESTER}}</div>
<!-- BODY -->
<footer>Generated by cyberdeck-arsenal v{{VERSION}}. Testing was limited to assets the client
confirmed they own or are authorised to test. Findings reflect the state of the systems at the
time of testing and should be re-validated after remediation.</footer>
</div></body></html>
"""

    @staticmethod
    def _fill_template(template: str, values: Dict[str, str], body: str) -> str:
        """Substitute ``{{TOKEN}}`` placeholders and the ``<!-- BODY -->`` marker.

        Deliberately avoids :meth:`str.format` so CSS braces or JavaScript in a
        user-supplied template are never interpreted as format fields.
        """
        rendered = template
        for token, value in values.items():
            rendered = rendered.replace("{{%s}}" % token, value)
        if "<!-- BODY -->" in rendered:
            rendered = rendered.replace("<!-- BODY -->", body)
        elif "{{BODY}}" in rendered:
            rendered = rendered.replace("{{BODY}}", body)
        else:
            rendered = rendered.replace("</div></body></html>", body + "</div></body></html>")
        return rendered

    def render_html(self) -> str:
        """Render a self-contained HTML report."""
        data = self.data
        counts = data.counts_by_severity()
        body: List[str] = []

        body.append('<div class="grid">')
        body.append(f'<div class="card"><div class="label">Overall risk</div>'
                    f'<div class="value">{html.escape(data.overall_risk())}</div></div>')
        body.append(f'<div class="card"><div class="label">Findings</div>'
                    f'<div class="value">{len(data.findings)}</div></div>')
        body.append(f'<div class="card"><div class="label">Critical / High</div>'
                    f'<div class="value">{counts.get("CRITICAL", 0)} / {counts.get("HIGH", 0)}</div></div>')
        body.append(f'<div class="card"><div class="label">Hosts</div>'
                    f'<div class="value">{len(data.hosts)}</div></div>')
        body.append(f'<div class="card"><div class="label">Open services</div>'
                    f'<div class="value">{data.open_port_count()}</div></div>')
        body.append(f'<div class="card"><div class="label">Artefacts</div>'
                    f'<div class="value">{len(data.artefacts)}</div></div>')
        body.append('</div>')

        body.append('<h2>Executive summary</h2>')
        body.append(f"<p>{html.escape(self._executive_paragraph())}</p>")

        body.append('<h2>Scope and methodology</h2>')
        body.append('<ul>')
        body.append(f'<li><strong>Scope:</strong> {html.escape(self.scope)}</li>')
        body.append('<li><strong>Approach:</strong> reconnaissance, enumeration, targeted '
                    'vulnerability checks and manual verification of high-severity results.</li>')
        body.append('<li><strong>Constraints:</strong> no denial-of-service testing, no '
                    'destructive payloads, no exfiltration beyond proof of exposure.</li>')
        body.append('</ul>')

        body.append('<h2>Findings summary</h2>')
        body.append('<table><thead><tr><th>#</th><th>Severity</th><th>Finding</th>'
                    '<th>Host</th><th>Category</th></tr></thead><tbody>')
        for index, finding in enumerate(data.findings, start=1):
            body.append(
                f'<tr><td>{index}</td>'
                f'<td><span class="severity {finding.severity}">{finding.severity}</span></td>'
                f'<td>{html.escape(finding.title)}</td>'
                f'<td>{html.escape(finding.host or "-")}</td>'
                f'<td>{html.escape(finding.category)}</td></tr>')
        if not data.findings:
            body.append('<tr><td>-</td><td><span class="severity INFO">INFO</span></td>'
                        '<td>No findings were identified</td><td>-</td><td>-</td></tr>')
        body.append('</tbody></table>')

        body.append('<h2>Detailed findings</h2>')
        for index, finding in enumerate(data.findings, start=1):
            body.append(f'<div class="finding {finding.severity}">')
            body.append(f'<h3>{index}. {html.escape(finding.title)}</h3>')
            body.append(f'<div class="meta"><span class="severity {finding.severity}">'
                        f'{finding.severity}</span> &middot; {html.escape(finding.category)}'
                        + (f' &middot; {html.escape(finding.host)}'
                           + (f':{html.escape(str(finding.port))}' if finding.port else '')
                           if finding.host else '')
                        + (f' &middot; source: {html.escape(finding.source)}'
                           if finding.source else '') + '</div>')
            if finding.description:
                body.append(f'<span class="label">Description</span>'
                            f'<p>{html.escape(finding.description)}</p>')
            body.append('<span class="label">Evidence</span>')
            body.append(f'<pre>{html.escape(finding.evidence or "See appendix artefacts.")}</pre>')
            body.append('<span class="label">Remediation</span>')
            body.append(f'<p>{html.escape(finding.suggest_remediation())}</p>')
            if finding.references:
                body.append('<span class="label">References</span><ul>')
                for reference in finding.references:
                    if reference:
                        body.append(f'<li><a href="{html.escape(reference)}" rel="noopener">'
                                    f'{html.escape(reference[:120])}</a></li>')
                body.append('</ul>')
            body.append('</div>')

        body.append('<h2>Host inventory</h2>')
        if data.hosts:
            body.append('<table><thead><tr><th>Host</th><th>Name</th><th>OS guess</th>'
                        '<th>Open ports</th></tr></thead><tbody>')
            for host in sorted(data.hosts.values(), key=lambda entry: entry["ip"]):
                ports = ", ".join(
                    f"{port['port']}/{port['service']}"
                    + (f" ({html.escape(port['version'][:30])})" if port.get("version") else "")
                    for port in sorted(host.get("ports", []),
                                       key=lambda port: int(port["port"] or 0)))
                body.append(f"<tr><td>{html.escape(host['ip'])}</td>"
                            f"<td>{html.escape(host['hostname'] or '-')}</td>"
                            f"<td>{html.escape(host['os'] or 'unknown')}</td>"
                            f"<td>{ports or '-'}</td></tr>")
            body.append('</tbody></table>')
        else:
            body.append('<p>No host inventory was captured.</p>')

        if data.osint:
            body.append('<h2>Public information exposure (OSINT)</h2><ul>')
            emails = data.osint.get("emails", [])
            subdomains = data.osint.get("subdomains", [])
            if emails:
                body.append(f'<li><strong>Emails ({len(emails)}):</strong> '
                            + ", ".join(html.escape(email) for email in emails[:25]) + '</li>')
            if subdomains:
                body.append(f'<li><strong>Subdomains ({len(subdomains)}):</strong> '
                            + ", ".join(html.escape(host) for host in subdomains[:25]) + '</li>')
            for note in data.osint.get("notes", [])[:10]:
                body.append(f'<li>{html.escape(str(note))}</li>')
            body.append('</ul>')

        body.append('<h2>Timeline</h2>')
        body.append('<table><thead><tr><th>Timestamp</th><th>Artefact</th></tr></thead><tbody>')
        for timestamp, artefact in data.timeline[:100]:
            body.append(f'<tr><td>{html.escape(timestamp)}</td>'
                        f'<td><code>{html.escape(artefact)}</code></td></tr>')
        body.append('</tbody></table>')

        body.append('<h2>Appendix A - artefacts</h2>')
        body.append('<table><thead><tr><th>Artefact</th><th>Size (bytes)</th>'
                    '<th>SHA-256</th></tr></thead><tbody>')
        for artefact in data.artefacts[:200]:
            body.append(f'<tr><td><code>{html.escape(artefact.path)}</code></td>'
                        f'<td>{artefact.size}</td>'
                        f'<td><code>{html.escape(artefact.sha256 or "see chain-of-custody log")}'
                        f'</code></td></tr>')
        body.append('</tbody></table>')

        if data.errors:
            body.append('<h2>Appendix B - collection notes</h2><ul>')
            for error in data.errors[:40]:
                body.append(f'<li>{html.escape(error)}</li>')
            body.append('</ul>')

        template_path = self.templates_dir / "report_template.html"
        template = self.HTML_TEMPLATE_FALLBACK
        if template_path.is_file():
            try:
                template = template_path.read_text()
            except OSError as exc:
                self.logger.debug(f"could not read {template_path}: {exc}")

        values = {
            "CLIENT": html.escape(self.client),
            "GENERATED": html.escape(self.generated),
            "TESTER": html.escape(self.tester),
            "SCOPE": html.escape(self.scope),
            "VERSION": __version__,
            "RISK": html.escape(data.overall_risk()),
        }
        rendered = self._fill_template(template, values, "\n".join(body))
        # Guard against a template that omits the body marker or the findings
        if "<h2>Detailed findings</h2>" not in rendered:
            self.logger.debug("template did not accept the body - using the built-in template")
            rendered = self._fill_template(self.HTML_TEMPLATE_FALLBACK, values, "\n".join(body))
        return rendered

    # -- executive summary -------------------------------------------------- #
    def render_executive(self) -> str:
        """Render the one-page executive summary."""
        data = self.data
        counts = data.counts_by_severity()
        lines = [
            f"# Executive summary: {self.client}",
            "",
            f"**Assessment date**: {self.generated[:10]}  ",
            f"**Prepared by**: {self.tester}  ",
            f"**Overall risk rating**: {data.overall_risk()}",
            "",
            "## What we did",
            "",
            f"{self.scope}. Testing combined reconnaissance, network and service "
            f"enumeration, targeted vulnerability checks, and manual verification of the "
            f"results that mattered.",
            "",
            "## What we found",
            "",
            self._executive_paragraph(),
            "",
            "| Severity | Count |",
            "|---|---|",
        ]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            lines.append(f"| {severity.title()} | {counts.get(severity, 0)} |")
        lines.append("")
        top = [finding for finding in data.findings if finding.severity_rank >= 3][:7]
        if top:
            lines.append("## What to fix first")
            lines.append("")
            for index, finding in enumerate(top, start=1):
                lines.append(f"{index}. **{finding.title}** - {finding.suggest_remediation()}")
            lines.append("")
        else:
            lines.append("## What to fix first")
            lines.append("")
            lines.append("No critical or high severity issues were identified. Address the "
                         "medium and low findings through normal change control.")
            lines.append("")
        lines.append("## What happens next")
        lines.append("")
        lines.append("1. Confirm the findings with the technical team and agree owners.")
        lines.append("2. Remediate critical and high findings within 72 hours.")
        lines.append("3. Remediate medium findings within 30 days, low findings within 90 days.")
        lines.append("4. Re-test to confirm the fixes; the raw evidence is retained so results "
                     "can be reproduced.")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("The full technical report, including evidence and remediation detail, "
                     "accompanies this summary.")
        return "\n".join(lines)

    # -- CSV / JSON --------------------------------------------------------- #
    def write_findings_csv(self, path: Path) -> Path:
        """Write findings to CSV."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "severity", "title", "category", "host", "port", "description",
                "evidence", "remediation", "source"])
            writer.writeheader()
            for finding in self.data.findings:
                row = finding.as_dict()
                row["remediation"] = finding.suggest_remediation()
                writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
        return path

    def write_bundle_json(self, path: Path) -> Path:
        """Write the complete machine-readable bundle."""
        payload = {
            "generated": self.generated,
            "client": self.client,
            "scope": self.scope,
            "tester": self.tester,
            "overall_risk": self.data.overall_risk(),
            "counts": self.data.counts_by_severity(),
            "findings": [
                {**finding.as_dict(), "remediation": finding.suggest_remediation()}
                for finding in self.data.findings],
            "hosts": list(self.data.hosts.values()),
            "artefacts": [
                {"path": a.path, "size": a.size, "kind": a.kind, "sha256": a.sha256}
                for a in self.data.artefacts],
            "timeline": [{"ts": ts, "artefact": artefact} for ts, artefact in self.data.timeline],
            "osint": self.data.osint,
            "collection_notes": self.data.errors,
            "generator": f"cyberdeck-arsenal report_generator v{__version__}",
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str) + "\n")
        return path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="report_generator.py",
        description="generate markdown/HTML/executive reports from an engagement directory",
        epilog="Also available as: cdeck report <dir>")
    parser.add_argument("directory", help="engagement directory containing scan output")
    parser.add_argument("--formats", default="md,html,exec,csv,json",
                        help="comma-separated: md,html,exec,csv,json (default: all)")
    parser.add_argument("--output", default=None,
                        help="output directory (default: the engagement directory)")
    parser.add_argument("--client", default="", help="client or asset owner name")
    parser.add_argument("--scope", default="Internal network and web application",
                        help="scope description for the report header")
    parser.add_argument("--tester", default="", help="tester name for the report header")
    parser.add_argument("--name", default="report", help="base filename for the outputs")
    parser.add_argument("--print-findings", action="store_true",
                        help="also print the finding list to the console")
    parser.add_argument("--version", action="version", version=f"report_generator {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("report_generator", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)))

    directory = Path(args.directory).expanduser()
    if not directory.is_dir():
        logger.error(f"engagement directory not found: {directory}")
        return 2

    logger.banner("report generator", str(directory))
    data = ReportData(directory, logger)
    data.collect()
    logger.info(f"parsed {len(data.artefacts)} artefact(s), {len(data.hosts)} host(s), "
                f"{len(data.findings)} finding(s)")

    if data.errors:
        for error in data.errors[:5]:
            logger.warn(error)

    builder = ReportBuilder(data, config, logger, client=args.client, scope=args.scope,
                            tester=args.tester)
    output_dir = Path(args.output).expanduser() if args.output else directory
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = {token.strip().lower() for token in args.formats.split(",") if token.strip()}
    written: List[Path] = []

    if "md" in formats or "markdown" in formats:
        path = output_dir / f"{args.name}.md"
        path.write_text(builder.render_markdown())
        written.append(path)
    if "html" in formats:
        path = output_dir / f"{args.name}.html"
        path.write_text(builder.render_html())
        written.append(path)
    if "exec" in formats or "executive" in formats:
        path = output_dir / "EXECUTIVE_SUMMARY.md"
        path.write_text(builder.render_executive())
        written.append(path)
    if "csv" in formats:
        written.append(builder.write_findings_csv(output_dir / f"{args.name}_findings.csv"))
    if "json" in formats:
        written.append(builder.write_bundle_json(output_dir / f"{args.name}_bundle.json"))

    for path in written:
        logger.ok(f"wrote {path}")
        print(colour(f"    {path}", C.DIM))

    print()
    print(colour(f"  Overall risk rating: {data.overall_risk()}", C.BOLD))
    counts = data.counts_by_severity()
    print(f"  critical {counts.get('CRITICAL', 0)} · high {counts.get('HIGH', 0)} · "
          f"medium {counts.get('MEDIUM', 0)} · low {counts.get('LOW', 0)} · "
          f"info {counts.get('INFO', 0)}")

    if args.print_findings:
        print()
        for index, finding in enumerate(data.findings, start=1):
            severity_colour = (C.BRIGHT_RED if finding.severity in ("CRITICAL", "HIGH")
                               else C.YELLOW if finding.severity == "MEDIUM" else C.DIM)
            print(f"  {index:>3}. {colour(finding.severity, severity_colour):<18} "
                  f"{finding.title[:96]}")

    if not written:
        logger.warn("no output formats selected - nothing was written")
        return 1

    # Record for the HUD's recon panel
    try:
        from cyberlib import Database  # type: ignore
        with Database("events", logger=logger) as db:
            db.event("report_generator", "report",
                     f"report generated for {directory.name}: {data.overall_risk()} risk, "
                     f"{len(data.findings)} finding(s)", "INFO",
                     {"directory": str(directory), "risk": data.overall_risk(),
                      "findings": len(data.findings)})
    except Exception:  # noqa: BLE001
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
