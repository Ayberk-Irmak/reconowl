"""Passive reconnaissance — intelligence gathered without touching the target.

Sources (all reliable, key-free, JSON/DNS APIs):
- **DNS** records via dnspython.
- **RDAP** (modern WHOIS) over HTTP for registration data.
- **crt.sh** certificate transparency for subdomains.
- **Wayback Machine / Common Crawl** for historically-known URLs and endpoints.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from ..config import ScanConfig
from ..models import ScanResult
from ..utils import dnsx


def _rdap(host: str, timeout: float = 12.0) -> dict:
    """Fetch registration data via RDAP (rdap.org aggregates registries)."""
    url = f"https://rdap.org/domain/{urllib.parse.quote(host)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconowl/0.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - RDAP may not cover every TLD
        return {}

    out: dict = {"handle": data.get("handle", "")}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    out["registered"] = events.get("registration", "")
    out["expires"] = events.get("expiration", "")
    out["last_changed"] = events.get("last changed", "")
    out["status"] = data.get("status", [])
    registrars = [
        e.get("vcardArray", [None, []])[1]
        for e in data.get("entities", [])
        if "registrar" in (e.get("roles") or [])
    ]
    for vcard in registrars:
        for field in vcard or []:
            if field and field[0] == "fn":
                out["registrar"] = field[3]
                break
    out["nameservers"] = sorted(
        ns.get("ldhName", "") for ns in data.get("nameservers", []) if ns.get("ldhName")
    )
    return out


def _certspotter_subdomains(host: str, timeout: float = 20.0) -> set[str]:
    """Fast subdomain source: SSLMate's Cert Spotter CT API (JSON)."""
    url = (
        f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(host)}"
        "&include_subdomains=true&expand=dns_names"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconowl/0.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return set()
    found: set[str] = set()
    for entry in data:
        for name in entry.get("dns_names", []) or []:
            name = str(name).strip().lstrip("*.").lower()
            if name.endswith(host.lower()) and "@" not in name:
                found.add(name)
    return found


def _crtsh_subdomains(host: str, timeout: float = 15.0) -> set[str]:
    """Enumerate subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(host)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconowl/0.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - crt.sh is often slow/rate-limited
        return set()

    found: set[str] = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(host.lower()) and "@" not in name:
                found.add(name)
    return found


def _subdomains_from_urls(host: str, urls: list[str]) -> set[str]:
    """Derive subdomains from already-harvested URLs (free extra coverage)."""
    found: set[str] = set()
    for url in urls:
        netloc = urllib.parse.urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
        if netloc.endswith(host.lower()):
            found.add(netloc)
    return found


def _wayback_urls(host: str, limit: int, timeout: float = 25.0) -> list[str]:
    """Harvest historically-archived URLs for the host from the Wayback CDX API."""
    params = [
        ("url", f"{host}*"),
        ("output", "json"),
        ("fl", "original"),
        ("collapse", "urlkey"),
        ("limit", str(limit)),
    ]
    url = "http://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconowl/0.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            rows = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - transient 503s happen; caller continues
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    return [str(r[0]) for r in rows[1:] if r]


def run(result: ScanResult, config: ScanConfig, ui) -> None:
    """Populate ``result`` with passive-recon assets."""
    host = result.target.host

    ui.info("Resolving DNS records…")
    result.dns_records = dnsx.resolve_records(host)
    if result.dns_records:
        a = result.dns_records.get("A", [])
        if a and not result.target.ip:
            result.target.ip = a[0]
        ui.good(f"DNS: {', '.join(f'{k}({len(v)})' for k, v in result.dns_records.items())}")
    else:
        ui.warn("No DNS records resolved.")

    if not result.target.is_ip:
        ui.info("Fetching WHOIS/RDAP registration data…")
        result.whois = _rdap(host, timeout=config.timeout)
        if result.whois.get("registrar"):
            ui.good(f"Registrar: {result.whois['registrar']}")

    ui.info("Harvesting archived URLs (Wayback Machine)…")
    urls = _wayback_urls(host, config.max_urls)
    result.urls = sorted(set(urls))[: config.max_urls]
    ui.good(f"Archived URLs: {len(result.urls)}")

    if not result.target.is_ip:
        ui.info("Enumerating subdomains (Cert Spotter + crt.sh + archives)…")
        subs: set[str] = set()
        subs |= _certspotter_subdomains(host, timeout=config.timeout + 8)
        subs |= _crtsh_subdomains(host)
        subs |= _subdomains_from_urls(host, result.urls)
        result.subdomains = sorted(subs)
        ui.good(f"Subdomains found: {len(result.subdomains)}")
