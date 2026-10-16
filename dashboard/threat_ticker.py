#!/usr/bin/env python3
"""
threat_ticker.py - OSINT threat feed ticker for cyberdeck-arsenal
================================================================

Description
-----------
Pulls indicators of compromise, malicious IPs, exploited CVEs and threat
intelligence from a configurable set of public sources, caches them on disk and
displays them as a scrolling ticker.

Sources (all optional; anything without a key degrades gracefully):
    * AbuseIPDB        - reported malicious IP addresses      (api_keys.abuseipdb)
    * AlienVault OTX   - pulses / IOCs                        (api_keys.alienvault_otx)
    * GreyNoise        - internet noise / scanners            (api_keys.greynoise)
    * Shodan           - trending search queries              (api_keys.shodan)
    * CISA KEV         - known exploited vulnerabilities      (no key required)
    * NVD              - most recently published CVEs         (api_keys.nvd optional)

Results are cached in <install>/data/threat_cache.json so the ticker keeps
working offline and stays inside API rate limits.

Author      : cyberdeck-arsenal contributors
Version     : 1.0.0
Dependencies: cyberlib; requests; rich (optional for the scrolling display)
Licence     : MIT - read-only use of public APIs, honour their terms of service

Usage
-----
    cdeck threats
    python3 dashboard/threat_ticker.py --once
    python3 dashboard/threat_ticker.py --source kev --source nvd --limit 40
    python3 dashboard/threat_ticker.py --json > iocs.json
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
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
        C, Config, Database, Logger, colour, deps, now_iso, read_json, write_json,
    )
except ImportError as exc:
    print(f"threat_ticker: cannot import cyberlib ({exc})", file=sys.stderr)
    sys.exit(1)

__version__ = "1.0.0"

USER_AGENT = f"cyberdeck-arsenal/{__version__} (+https://github.com/GeorgeH466/fluffy-octo-couscous)"

#: Severity buckets keyed on the numeric CVSS score
def severity_for_score(score: Optional[float]) -> str:
    """Map a CVSS score onto a ticker severity label."""
    if score is None:
        return "INFO"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


SEVERITY_COLOURS: Dict[str, str] = {
    "CRITICAL": "#ff5555", "HIGH": "#ffb86c", "MEDIUM": "#f1fa8c",
    "LOW": "#8bd5ff", "INFO": "#6272a4", "KILLED": "#ff79c6",
}


@dataclass
class ThreatItem:
    """A single indicator, CVE or intel entry."""

    source: str
    kind: str                       # ip | cve | pulse | query | domain | hash
    title: str
    value: str = ""
    severity: str = "INFO"
    score: Optional[float] = None
    description: str = ""
    reference: str = ""
    published: str = ""
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for JSON output and the cache file."""
        return asdict(self)

    def render(self, width: int = 108) -> str:
        """Return a single-line ticker string."""
        badge = f"[{self.severity:<8}]"
        source = f"{self.source:<11}"
        value = self.value or self.title
        if len(value) > 34:
            value = value[:31] + "..."
        detail = self.description.replace("\n", " ")
        remaining = max(20, width - (len(badge) + len(source) + len(value) + 12))
        if len(detail) > remaining:
            detail = detail[:remaining - 3] + "..."
        score = f"{self.score:.1f}" if self.score is not None else "  - "
        return f"{badge} {score} {source} {value:<34} {detail}"


# --------------------------------------------------------------------------- #
# Feed implementations
# --------------------------------------------------------------------------- #
class Feeds:
    """Collection of OSINT feed fetchers sharing one HTTP session."""

    KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json")
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: Config, logger: Logger) -> None:
        """Bind feeds to configuration and a logger."""
        self.config = config
        self.logger = logger
        self.session: Optional[Any] = None
        if deps.have_module("requests"):
            import requests  # type: ignore
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})

    # -- helpers ------------------------------------------------------------ #
    def _key(self, name: str) -> str:
        """Return an API key from the configuration (empty when unset)."""
        return str(self.config.get(f"api_keys.{name}", "") or "").strip()

    def _get(self, url: str, headers: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, Any]] = None, timeout: float = 15.0) -> Optional[Any]:
        """Perform a GET returning parsed JSON, or None on any failure."""
        if not self.session:
            self.logger.debug("requests not installed - skipping HTTP feeds")
            return None
        try:
            response = self.session.get(url, headers=headers or {}, params=params or {},
                                        timeout=timeout)
            if response.status_code == 429:
                self.logger.warn(f"rate limited by {url.split('/')[2]} - using cached data")
                return None
            if response.status_code >= 400:
                self.logger.debug(f"HTTP {response.status_code} from {url}")
                return None
            return response.json()
        except Exception as exc:  # noqa: BLE001 - feeds are best effort
            self.logger.debug(f"feed request failed ({url.split('/')[2]}): {exc}")
            return None

    @staticmethod
    def _strip(text: str) -> str:
        """Remove HTML tags and entities, collapse whitespace."""
        text = re.sub(r"<[^>]+>", " ", text or "")
        return re.sub(r"\s+", " ", html.unescape(text)).strip()

    # -- sources ------------------------------------------------------------ #
    def abuseipdb(self, limit: int = 25) -> List[ThreatItem]:
        """Fetch the blacklist of the worst reported IPs from AbuseIPDB."""
        key = self._key("abuseipdb")
        if not key:
            self.logger.debug("abuseipdb: no API key configured")
            return []
        data = self._get("https://api.abuseipdb.com/api/v2/blacklist",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"confidenceMinimum": 90, "limit": min(limit, 100)})
        items: List[ThreatItem] = []
        for entry in (data or {}).get("data", [])[:limit]:
            score = float(entry.get("abuseConfidenceScore", 0))
            items.append(ThreatItem(
                source="AbuseIPDB", kind="ip",
                title=f"Malicious IP {entry.get('ipAddress')}",
                value=str(entry.get("ipAddress", "")),
                severity="HIGH" if score >= 90 else "MEDIUM",
                score=score / 10.0,
                description=(f"{entry.get('totalReports', 0)} reports, "
                             f"country {entry.get('countryCode', '??')}, "
                             f"last seen {entry.get('lastReportedAt', 'unknown')}"),
                reference=f"https://www.abuseipdb.com/check/{entry.get('ipAddress')}",
                published=str(entry.get("lastReportedAt", ""))))
        return items

    def otx(self, limit: int = 25) -> List[ThreatItem]:
        """Fetch the most recent AlienVault OTX pulses."""
        key = self._key("alienvault_otx")
        if not key:
            self.logger.debug("otx: no API key configured")
            return []
        data = self._get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                         headers={"X-OTX-API-KEY": key}, params={"limit": min(limit, 50)})
        items: List[ThreatItem] = []
        for pulse in (data or {}).get("results", [])[:limit]:
            indicators = pulse.get("indicators", [])
            sample = ", ".join(str(i.get("indicator", "")) for i in indicators[:3])
            items.append(ThreatItem(
                source="OTX", kind="pulse",
                title=self._strip(pulse.get("name", "untitled pulse"))[:80],
                value=str(pulse.get("id", ""))[:34],
                severity="MEDIUM",
                description=(f"{len(indicators)} indicators"
                             + (f" ({sample})" if sample else "")
                             + " " + self._strip(pulse.get("description", ""))[:120]),
                reference=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                published=str(pulse.get("modified", "")),
                tags=[str(t) for t in pulse.get("tags", [])][:5]))
        return items

    def greynoise(self, limit: int = 20) -> List[ThreatItem]:
        """Query GreyNoise for currently active scanners and their intent."""
        key = self._key("greynoise")
        if not key:
            self.logger.debug("greynoise: no API key configured")
            return []
        data = self._get("https://api.greynoise.io/v3/community/query",
                         headers={"key": key}, params={"size": min(limit, 100)})
        items: List[ThreatItem] = []
        for entry in (data or {}).get("data", [])[:limit]:
            classification = str(entry.get("classification", "unknown"))
            items.append(ThreatItem(
                source="GreyNoise", kind="ip",
                title=f"{classification.upper()} scanner {entry.get('ip')}",
                value=str(entry.get("ip", "")),
                severity="HIGH" if classification.lower() == "malicious" else "LOW",
                description=(f"{entry.get('name') or 'unnamed'} · "
                             f"actor {entry.get('actor', 'unknown')} · "
                             f"last seen {entry.get('last_seen', 'unknown')}"),
                reference="https://viz.greynoise.io/",
                published=str(entry.get("last_seen", ""))))
        return items

    def shodan(self, limit: int = 20) -> List[ThreatItem]:
        """Fetch trending Shodan queries as an indicator of current activity."""
        key = self._key("shodan")
        if not key:
            self.logger.debug("shodan: no API key configured")
            return []
        data = self._get("https://api.shodan.io/shodan/host/search",
                         params={"key": key, "query": "product:nginx",
                                 "minify": "true", "facets": "country"})
        items: List[ThreatItem] = []
        for match in (data or {}).get("matches", [])[:limit]:
            location = match.get("location", {}) or {}
            items.append(ThreatItem(
                source="Shodan", kind="host",
                title=f"Exposed service on {match.get('ip_str')}",
                value=str(match.get("ip_str", "")),
                severity="MEDIUM",
                description=(f"port {match.get('port')} · {match.get('product', 'unknown')} · "
                             f"{location.get('country_name', '??')} "
                             f"{location.get('city', '')}").strip(),
                reference=f"https://www.shodan.io/host/{match.get('ip_str')}",
                published=str(match.get("timestamp", ""))))
        return items

    def cisa_kev(self, limit: int = 30) -> List[ThreatItem]:
        """Fetch the CISA Known Exploited Vulnerabilities catalogue (no key)."""
        data = self._get(self.KEV_URL, timeout=25.0)
        items: List[ThreatItem] = []
        if not data:
            return items
        vulnerabilities = sorted(data.get("vulnerabilities", []),
                                 key=lambda v: v.get("dateAdded", ""), reverse=True)
        for entry in vulnerabilities[:limit]:
            ransomware = str(entry.get("knownRansomwareCampaignUse", "Unknown")).lower()
            severity = "CRITICAL" if ransomware == "known" else "HIGH"
            items.append(ThreatItem(
                source="CISA-KEV", kind="cve",
                title=f"{entry.get('cveID')} {self._strip(entry.get('vulnerabilityName', ''))}"[:90],
                value=str(entry.get("cveID", "")),
                severity=severity,
                score=None,
                description=(f"{entry.get('vendorProject', '?')} {entry.get('product', '?')} · "
                             f"added {entry.get('dateAdded', '?')} · "
                             f"due {entry.get('dueDate', '?')} · "
                             f"ransomware: {entry.get('knownRansomwareCampaignUse', 'unknown')}"),
                reference=entry.get("notes", "") or "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                published=str(entry.get("dateAdded", ""))))
        return items

    def nvd_recent(self, limit: int = 25) -> List[ThreatItem]:
        """Fetch the most recently published CVEs from the NVD (key optional)."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(max(limit, 1), 100),
        }
        headers = {}
        key = self._key("nvd")
        if key:
            headers["apiKey"] = key
        data = self._get(self.NVD_URL, headers=headers, params=params, timeout=25.0)
        items: List[ThreatItem] = []
        for entry in (data or {}).get("vulnerabilities", [])[:limit]:
            cve = entry.get("cve", {})
            metrics = cve.get("metrics", {})
            score: Optional[float] = None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(metric_key):
                    try:
                        score = float(metrics[metric_key][0]["cvssData"]["baseScore"])
                        break
                    except (KeyError, IndexError, ValueError):
                        continue
            descriptions = cve.get("descriptions", [])
            description = next((d.get("value", "") for d in descriptions
                                if d.get("lang") == "en"), "")
            items.append(ThreatItem(
                source="NVD", kind="cve",
                title=f"{cve.get('id')} {self._strip(description)[:70]}",
                value=str(cve.get("id", "")),
                severity=severity_for_score(score), score=score,
                description=self._strip(description)[:220],
                reference=f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                published=str(cve.get("published", ""))))
        return items

    def all_sources(self) -> Dict[str, Callable[[int], List[ThreatItem]]]:
        """Return the mapping of source name to fetcher."""
        return {
            "abuseipdb": self.abuseipdb,
            "otx": self.otx,
            "greynoise": self.greynoise,
            "shodan": self.shodan,
            "kev": self.cisa_kev,
            "nvd": self.nvd_recent,
        }


class ThreatTicker:
    """Aggregates, caches and displays threat intelligence."""

    def __init__(self, config: Optional[Config] = None, logger: Optional[Logger] = None) -> None:
        """Set up the ticker, its cache path and its feed collection."""
        self.config = config or Config().load()
        self.logger = logger or Logger("threat_ticker",
                                       str(self.config.get("general.log_level", "INFO")))
        install = Path(self.config.get("general.install_dir", "/opt/cyberdeck-arsenal"))
        data_dir = install / "data"
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            data_dir = Path.home() / ".cyberdeck-arsenal" / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = data_dir / "threat_cache.json"
        self.ttl = int(self.config.get("api_keys.cache_ttl", 900))
        self.feeds = Feeds(self.config, self.logger)

    # -- cache -------------------------------------------------------------- #
    def _load_cache(self) -> Dict[str, Any]:
        """Read the cache file, returning an empty skeleton on failure."""
        cached = read_json(self.cache_path, default={}) or {}
        if not isinstance(cached, dict):
            cached = {}
        cached.setdefault("fetched_at", 0)
        cached.setdefault("items", [])
        return cached

    def _cache_age(self) -> float:
        """Seconds since the cache was last refreshed."""
        cached = self._load_cache()
        try:
            return max(0.0, time.time() - float(cached.get("fetched_at", 0)))
        except (TypeError, ValueError):
            return 1e12

    def fetch_all(self, force: bool = False, sources: Optional[Sequence[str]] = None,
                  limit: int = 30) -> List[ThreatItem]:
        """Return threat items, refreshing from the network when the cache is stale."""
        if not force and self._cache_age() < self.ttl:
            self.logger.debug(f"using cached threat data (age {int(self._cache_age())}s)")
            return [ThreatItem(**item) for item in self._load_cache().get("items", [])
                    if isinstance(item, dict)]

        available = self.feeds.all_sources()
        wanted = [s for s in (sources or available.keys()) if s in available]
        items: List[ThreatItem] = []
        fetched_any = False
        for name in wanted:
            try:
                produced = available[name](limit)
            except Exception as exc:  # noqa: BLE001
                self.logger.debug(f"{name} feed failed: {exc}")
                produced = []
            if produced:
                fetched_any = True
                self.logger.info(f"{name}: {len(produced)} item(s)")
            items.extend(produced)

        if fetched_any:
            items.sort(key=lambda item: (item.published or "", item.title), reverse=True)
            write_json(self.cache_path, {"fetched_at": time.time(), "fetched_iso": now_iso(),
                                         "items": [item.as_dict() for item in items]})
            self.logger.ok(f"threat cache updated ({len(items)} items)")
        else:
            cached_items = self._load_cache().get("items", [])
            if cached_items:
                self.logger.warn("no live feeds available - showing cached intelligence")
                items = [ThreatItem(**item) for item in cached_items if isinstance(item, dict)]
            else:
                self.logger.warn("no live feeds available and the cache is empty")
                self.logger.info("configure api_keys in cyberdeck.conf for AbuseIPDB/OTX/GreyNoise/Shodan")
        return items

    # -- display ------------------------------------------------------------ #
    def summary(self, items: Sequence[ThreatItem]) -> str:
        """Return a compact textual summary of a set of items."""
        counts: Dict[str, int] = {}
        for item in items:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        parts = [f"{severity}: {count}" for severity, count in
                 sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]
        sources = sorted({item.source for item in items})
        return (f"{len(items)} items from {len(sources)} source(s) ({', '.join(sources) or 'none'}) "
                f"- {'  '.join(parts)}")

    def run_ticker(self, items: Sequence[ThreatItem], refresh: int, width: int = 110) -> int:
        """Scroll through *items* until interrupted."""
        try:
            from rich.console import Console, Group
            from rich.live import Live
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            return self._run_plain_ticker(items, width)

        console = Console()
        if not items:
            console.print(Panel("no threat intelligence available - check api_keys in cyberdeck.conf",
                                title="threat ticker", border_style="yellow"))
            return 0

        def build(index: int) -> Panel:
            table = Table.grid(padding=(0, 1), expand=True)
            table.add_column("badge", width=11)
            table.add_column("score", width=5, justify="right")
            table.add_column("source", width=12)
            table.add_column("value", width=34)
            table.add_column("detail")
            for offset in range(10):
                item = items[(index + offset) % len(items)]
                colour_code = SEVERITY_COLOURS.get(item.severity, "#8bd5ff")
                detail = item.description.replace("\n", " ")[:70]
                table.add_row(
                    Text(f"[{item.severity}]", style=f"bold {colour_code}"),
                    Text(f"{item.score:.1f}" if item.score is not None else "-", style="dim"),
                    Text(item.source, style="#00ffd5"),
                    Text((item.value or item.title)[:34], style="#8bd5ff"),
                    Text(detail + ("  " + item.reference if item.reference and offset == 0 else ""),
                         style="dim"))
            header = Text()
            header.append("  OSINT THREAT TICKER  ", style="bold #00ffd5")
            header.append(f"{len(items)} indicators  ", style="dim")
            header.append(f"refreshed {datetime.now().strftime('%H:%M:%S')}  ", style="dim")
            header.append(f"cache age {int(self._cache_age())}s", style="dim")
            return Panel(Group(header, Text(""), table),
                         border_style="#5a6b7a",
                         subtitle="q to quit · r to refresh feeds")

        index = 0
        with Live(build(index), console=console, refresh_per_second=4, screen=True) as live:
            last_refresh = time.time()
            while True:
                index = (index + 1) % max(1, len(items))
                live.update(build(index))
                time.sleep(max(0.4, refresh / 4.0))
                if time.time() - last_refresh > self.ttl:
                    items = self.fetch_all(force=True)
                    last_refresh = time.time()
        return 0

    def _run_plain_ticker(self, items: Sequence[ThreatItem], width: int) -> int:
        """Non-rich fallback: print the feed and exit."""
        if not items:
            print("threat ticker: no intelligence available (configure api_keys in cyberdeck.conf)")
            return 0
        print(colour(f"  OSINT THREAT TICKER  ::  {self.summary(items)}", C.BRIGHT_CYAN))
        print()
        for item in items[:40]:
            print("  " + item.render(width))
        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="threat_ticker.py",
        description="OSINT threat feed ticker (AbuseIPDB, OTX, GreyNoise, Shodan, CISA KEV, NVD)",
        epilog="Also available as: cdeck threats")
    parser.add_argument("--refresh", type=int, default=None,
                        help="ticker speed in seconds per cycle (default 8)")
    parser.add_argument("--limit", type=int, default=30, help="items requested per source")
    parser.add_argument("--source", action="append", default=None,
                        choices=["abuseipdb", "otx", "greynoise", "shodan", "kev", "nvd"],
                        help="restrict to specific sources (repeatable)")
    parser.add_argument("--force", action="store_true", help="ignore the cache and refetch")
    parser.add_argument("--once", action="store_true", help="print the feed once and exit")
    parser.add_argument("--json", action="store_true", help="emit the feed as JSON")
    parser.add_argument("--record", action="store_true",
                        help="write a summary into the shared events database")
    parser.add_argument("--width", type=int, default=110, help="ticker line width")
    parser.add_argument("--version", action="version", version=f"threat_ticker {__version__}")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = Config().load()
    logger = Logger("threat_ticker", str(config.get("general.log_level", "INFO")),
                    bool(config.get("general.color_output", True)))
    ticker = ThreatTicker(config, logger)

    items = ticker.fetch_all(force=args.force, sources=args.source, limit=args.limit)
    logger.info(ticker.summary(items))

    if args.record and items:
        try:
            with Database("events", logger=logger) as db:
                db.event("threat_ticker", "osint", ticker.summary(items), "INFO",
                         {"items": [item.as_dict() for item in items[:50]]})
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"could not record threat summary: {exc}")

    if args.json:
        print(json.dumps({
            "generated": now_iso(),
            "summary": ticker.summary(items),
            "items": [item.as_dict() for item in items],
        }, indent=2))
        return 0

    if args.once:
        return ticker._run_plain_ticker(items, args.width)  # noqa: SLF001 - intended API

    refresh = args.refresh or 8
    try:
        return ticker.run_ticker(items, refresh, args.width)
    except KeyboardInterrupt:
        print()
        logger.info("threat ticker stopped")
        return 0


if __name__ == "__main__":
    sys.exit(main())
