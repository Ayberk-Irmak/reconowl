"""CVSS v3.1 base-score computation and per-finding scoring.

Each finding category maps to a representative CVSS v3.1 base vector; unmapped
categories (and nuclei findings, whose severity comes from the template) fall
back to a vector chosen from the finding's own severity. The official base-score
formula turns the vector into a 0.0–10.0 score and a rating.
"""

from __future__ import annotations

import math

from .models import Finding, Severity

# --- CVSS v3.1 base metric weights ---------------------------------------- #
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: round up to the nearest 0.1."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_label(score: float) -> str:
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(vector: str) -> tuple[float, str]:
    """Compute ``(score, rating)`` from a CVSS v3.1 base vector string."""
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            key, val = part.split(":", 1)
            metrics[key] = val
    try:
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        scope = metrics["S"]
        pr = (_PR_C if scope == "C" else _PR_U)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return 0.0, "None"

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "C":
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    return score, severity_label(score)


# --- category -> vector mapping ------------------------------------------- #
_CATEGORY_VECTORS = {
    "command-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # 9.8
    "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                # 9.8
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                # 9.8
    "nosql-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     # 8.1
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",                # 9.3
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",                 # 7.5
    "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",                 # 7.5
    "prototype-pollution": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", # 8.1
    "subdomain-takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",  # 9.0
    "default-credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",                 # ~4.6
    "spf-permissive": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",       # ~7.4
    "spf-missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",          # ~4.6
    "spf-multiple": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",         # ~4.6
    "dmarc-missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",        # ~4.6
    "broken-access-control": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 6.5
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",                 # 6.1
    "crlf-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      # 6.1
    "open-redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",       # 6.1
    "host-header-injection": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "cors-reflect-origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "cors-null-origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "cors-wildcard-credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "cors-wildcard": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "jwt-weak-secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     # 8.1
    "jwt-alg-none": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",        # 8.1
    "jwt-no-exp": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "jwt-sensitive-claims": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "graphql-introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "graphql-ide": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "graphql-endpoint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "dir-listing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cookie-flags": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "version-disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "tls-expired": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "tls-self-signed": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "tls-untrusted": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "tls-weak-protocol": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

_PREFIX_VECTORS = {
    "missing-header:": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "cors-": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "tls-": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "dir-": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "jwt-": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "graphql-": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

_SEVERITY_FALLBACK = {
    Severity.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    Severity.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    Severity.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",    # 5.4
    Severity.LOW: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",       # 3.1
    Severity.INFO: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
}


def vector_for(finding: Finding) -> str:
    """Pick the CVSS vector for a finding: exact category, prefix, then severity."""
    cat = finding.category
    if cat in _CATEGORY_VECTORS:
        return _CATEGORY_VECTORS[cat]
    if not cat.startswith("nuclei:"):
        for prefix, vec in _PREFIX_VECTORS.items():
            if cat.startswith(prefix):
                return vec
    return _SEVERITY_FALLBACK.get(finding.severity, _SEVERITY_FALLBACK[Severity.INFO])


def score_finding(finding: Finding) -> None:
    """Attach cvss_score / cvss_severity / cvss_vector to a finding in place.

    Findings that already carry an authoritative score (e.g. a CVE's published
    CVSS) are left untouched.
    """
    if finding.cvss_score is not None:
        return
    vector = vector_for(finding)
    score, rating = base_score(vector)
    finding.cvss_score = score
    finding.cvss_severity = rating
    finding.cvss_vector = vector


def apply(findings: list[Finding]) -> None:
    for finding in findings:
        score_finding(finding)
