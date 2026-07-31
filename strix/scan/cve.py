"""Native check: known-CVE mapping from detected software versions.

Extracts (product, version) pairs from Server headers, nmap service banners, and
detected technologies, then matches them against a curated offline CVE database
(``data/cve_db.json``) using version-range comparison. Each hit becomes a finding
carrying the CVE's real CVSS and an NVD reference. The database is a high-signal
starter set — extend it, and pair it with nuclei for breadth.
"""

from __future__ import annotations

import json
import os
import re

from ..models import Finding, ScanResult, Severity

_SOURCE = "native:cve"
_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cve_db.json")
_NAME_VER = re.compile(r"([A-Za-z][A-Za-z0-9_\-. ]*?)[ :/v]+([0-9]+(?:\.[0-9]+)+[a-z0-9]*)")
_VER_NUM = re.compile(r"[0-9]+(?:\.[0-9]+)*")


def load_db(path: str = "") -> list[dict]:
    try:
        with open(path or _DB_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def parse_version(text: str) -> tuple[int, ...]:
    """Turn a version string into a comparable integer tuple (e.g. 2.4.7p1 -> (2,4,7))."""
    m = _VER_NUM.search(text or "")
    if not m:
        return ()
    return tuple(int(x) for x in m.group(0).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_matches(version: str, range_str: str) -> bool:
    """True if ``version`` satisfies a comma-separated constraint string."""
    v = parse_version(version)
    if not v:
        return False
    for constraint in range_str.split(","):
        constraint = constraint.strip()
        m = re.match(r"(>=|<=|==|!=|>|<|=)\s*(.+)", constraint)
        if not m:
            return False
        op, target = m.group(1), parse_version(m.group(2))
        c = _cmp(v, target)
        ok = {
            ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0,
            "==": c == 0, "=": c == 0, "!=": c != 0,
        }[op]
        if not ok:
            return False
    return True


def _alias_index(db: list[dict]) -> list[tuple[str, dict]]:
    """List of (alias, entry) sorted longest-alias-first for greedy matching."""
    pairs: list[tuple[str, dict]] = []
    for entry in db:
        for alias in [entry["product"], *entry.get("aliases", [])]:
            pairs.append((alias.lower(), entry))
    pairs.sort(key=lambda x: len(x[0]), reverse=True)
    return pairs


def _match_entry(name: str, alias_index) -> dict | None:
    low = name.lower()
    for alias, entry in alias_index:
        if re.search(rf"(?<![a-z]){re.escape(alias)}(?![a-z])", low):
            return entry
    return None


def extract_software(result: ScanResult) -> list[tuple[str, str, str]]:
    """Extract (raw-name, version, source) triples from recon assets."""
    out: list[tuple[str, str, str]] = []

    for p in result.ports:
        if p.product and p.version:
            out.append((p.product, p.version, f"port {p.number}/{p.protocol}"))

    for e in result.endpoints:
        if e.server:
            m = _NAME_VER.search(e.server)
            if m:
                out.append((m.group(1).strip(), m.group(2), f"Server header ({e.url})"))
        for tech in e.technologies:
            m = _NAME_VER.search(tech.replace(":", " "))
            if m:
                out.append((m.group(1).strip(), m.group(2), f"tech at {e.url}"))
    return out


def match(software: list[tuple[str, str, str]], db: list[dict]) -> list[dict]:
    """Return CVE hits: {product, version, cve, cvss, severity, desc, source}."""
    index = _alias_index(db)
    hits: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for name, version, source in software:
        entry = _match_entry(name, index)
        if entry is None:
            continue
        for cve in entry.get("cves", []):
            if not version_matches(version, cve["range"]):
                continue
            key = (entry["product"], version, cve["id"])
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "product": entry["product"], "version": version, "cve": cve["id"],
                "cvss": cve.get("cvss", 0.0), "severity": cve.get("severity", "Medium"),
                "desc": cve.get("desc", ""), "source": source,
            })
    return hits


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    if not getattr(config, "cve_lookup", True):
        return []
    db = load_db()
    hits = match(extract_software(result), db)
    findings: list[Finding] = []
    for h in hits:
        f = Finding(
            title=f"{h['product']} {h['version']} — {h['cve']}",
            severity=Severity.from_str(h["severity"]),
            target=result.target.host,
            category="cve",
            location=f"{h['product']} {h['version']}",
            description=f"{h['cve']}: {h['desc']} (detected via {h['source']}).",
            remediation=f"Upgrade {h['product']} to a fixed version.",
            evidence=f"{h['product']} {h['version']} matches {h['cve']}",
            source=_SOURCE,
            references=[f"https://nvd.nist.gov/vuln/detail/{h['cve']}"],
            extra={"cve": h["cve"], "product": h["product"], "version": h["version"]},
        )
        # Use the CVE's authoritative CVSS instead of the category heuristic.
        f.cvss_score = float(h["cvss"])
        f.cvss_severity = h["severity"]
        f.cvss_vector = f"({h['cve']} base score)"
        findings.append(f)
    return findings
