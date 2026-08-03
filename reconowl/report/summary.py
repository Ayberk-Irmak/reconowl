"""Executive summary + scan-coverage assessment, derived from the ScanResult.

Both are computed from real data (findings, WAF, and the ``errors`` list that the
engine records when a phase is truncated or blocked) — nothing is invented. The
coverage assessment is important for honest reporting: a partial scan must never
read as a clean bill of health.
"""

from __future__ import annotations

from ..models import ScanResult

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# Human-friendly labels for the finding categories that show up in the narrative.
_THEMES = {
    "sqli": "SQL injection", "xss": "cross-site scripting",
    "command-injection": "command injection", "lfi": "file inclusion / path traversal",
    "ssti": "template injection", "ssrf": "server-side request forgery",
    "xxe": "XML external entities", "nosql-injection": "NoSQL injection",
    "default-credentials": "default/weak credentials", "exposed-service": "exposed services",
    "exposed-panel": "exposed admin panels", "csrf": "missing CSRF protection",
    "broken-access-control": "broken access control", "idor": "insecure direct object references",
    "cors-reflect-origin": "CORS misconfiguration", "open-redirect": "open redirect",
    "host-header-injection": "host-header injection", "crlf-injection": "response splitting",
    "subdomain-takeover": "subdomain takeover", "graphql-ide": "exposed GraphQL tooling",
    "dmarc-missing": "email spoofing exposure", "spf-missing": "email spoofing exposure",
    "openapi-exposed": "exposed API specification",
}


def _theme(category: str) -> str:
    if category in _THEMES:
        return _THEMES[category]
    if category.startswith("missing-header"):
        return "missing security headers"
    if category.startswith("tls-"):
        return "TLS/certificate weaknesses"
    if category.startswith("jwt-"):
        return "JWT weaknesses"
    if category.startswith(("exposure", "dir-")):
        return "exposed files/paths"
    return category.replace("-", " ")


def _coverage_caveats(result: ScanResult) -> list[str]:
    """Human-readable caveats pulled from the engine's recorded incompleteness."""
    out: list[str] = []
    for e in result.errors:
        if e.startswith("scan incomplete"):
            out.append(e.split("scan incomplete:", 1)[1].strip().capitalize())
        elif "rate-limiting/blocking detected" in e:
            out.append("The target rate-limited or blocked requests; some checks backed "
                       "off and may be incomplete.")
    return out


def build_summary(result: ScanResult) -> dict:
    counts = result.severity_counts()
    findings = result.sorted_findings()
    total = sum(counts.values())
    actionable = counts["Critical"] + counts["High"] + counts["Medium"]
    caveats = _coverage_caveats(result)
    complete = not caveats
    top = findings[:5]

    host = result.target.host or result.target.raw

    # --- narrative ---------------------------------------------------------- #
    parts: list[str] = []
    breakdown = ", ".join(f"{counts[s]} {s.lower()}" for s in _SEV_ORDER)
    if total == 0:
        parts.append(f"reconowl scanned {host} and reported no findings.")
    else:
        parts.append(
            f"reconowl scanned {host} and reported {total} finding(s) "
            f"({breakdown})."
        )
    if findings and findings[0].cvss_score:
        f0 = findings[0]
        parts.append(
            f"The highest-rated issue is “{f0.title}” "
            f"(CVSS {f0.cvss_score:.1f}, {f0.severity.label})."
        )
    themes = []
    for f in findings:
        if f.severity.label in ("Critical", "High", "Medium"):
            th = _theme(f.category)
            if th not in themes:
                themes.append(th)
    if themes:
        shown = themes[:4]
        parts.append("Key risk areas: " + ", ".join(shown) +
                     ("," if len(themes) > 4 else "") + (" and others." if len(themes) > 4 else "."))
    if result.waf:
        parts.append(f"A WAF/security proxy ({result.waf}) sits in front of the target.")
    if not complete:
        parts.append(
            "⚠ Coverage was partial (see below) — treat the absence of high-severity "
            "findings as inconclusive for the parts that were not fully scanned."
        )

    return {
        "headline": (
            f"{actionable} actionable finding(s) on {host}"
            + (f" — highest CVSS {result.max_cvss():.1f}" if total else "")
            + ("" if complete else " · partial coverage")
        ),
        "narrative": " ".join(parts),
        "counts": counts,
        "max_cvss": result.max_cvss(),
        "top_findings": [
            {"title": f.title, "severity": f.severity.label,
             "cvss_score": f.cvss_score, "category": f.category, "location": f.location}
            for f in top
        ],
        "coverage": {
            "complete": complete,
            "caveats": caveats,
            "assets": {
                "subdomains": len(result.subdomains),
                "endpoints": len(result.endpoints),
                "open_ports": len(result.ports),
                "urls": len(result.urls),
            },
        },
    }
