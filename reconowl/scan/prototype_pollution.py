"""Native check: server-side prototype pollution (SSPP).

Black-box detection via a behavioural gadget: polluting Express/Node's
``json spaces`` property makes subsequent JSON responses pretty-print with that
indentation. If a compact JSON endpoint starts returning 10-space-indented JSON
only after we send ``{"__proto__":{"json spaces":10}}``, the server merged our
input into ``Object.prototype`` — confirmed SSPP.

Note: this mutates a (cosmetic) global property; the check restores it to 0
afterwards. Detection is confirmed only by the formatting change, so there are
effectively no false positives.
"""

from __future__ import annotations

import json
import urllib.parse

from ..models import Finding, Severity
from ..utils.net import HttpClient, in_scope

_SOURCE = "native:proto-pollution"

_INDENT = 10
_INDENT_MARK = "\n" + " " * _INDENT  # newline + 10 spaces == pretty-printed


def _pollute_body(spaces: int) -> str:
    return json.dumps({"__proto__": {"json spaces": spaces}})


def _looks_json(text: str) -> bool:
    s = (text or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def became_indented(baseline: str, after: str) -> bool:
    """True if a compact JSON baseline turned into 10-space-indented JSON."""
    return (
        _looks_json(after)
        and _INDENT_MARK in after
        and _INDENT_MARK not in (baseline or "")
    )


def _candidates(result, cap: int) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if in_scope(url, result.target.host) and url not in seen:
            seen.add(url)
            urls.append(url)

    for ep in result.endpoints:
        if "json" in (ep.content_type or "").lower():
            add(ep.url)
    for u in [e.url for e in result.endpoints] + result.urls:
        low = urllib.parse.urlsplit(u).path.lower()
        if "/api" in low or low.endswith(".json"):
            add(u)
    base = result.target.base_url
    if base:
        for path in ("api", "api/v1", "graphql", ""):
            add(urllib.parse.urljoin(base + "/", path) if path else base)
    return urls[:cap]


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = _candidates(result, cap=8)
    if not candidates:
        return []

    hdrs = {"Content-Type": "application/json"}
    base_url = result.target.base_url
    findings: list[Finding] = []

    for url in candidates:
        baseline = client.get(url)
        if not baseline.ok or not _looks_json(baseline.text):
            continue
        if _INDENT_MARK in baseline.text:
            continue  # already pretty-printed; can't use this gadget here

        # Attempt pollution: JSON body to the endpoint and base, plus a
        # query-string variant for parsers that pollute from the query.
        targets = [url] + ([base_url] if base_url and base_url != url else [])
        for target in targets:
            client.request("POST", target, headers=hdrs, data=_pollute_body(_INDENT),
                           allow_redirects=False)
        qsep = "&" if "?" in url else "?"
        client.get(url + qsep + urllib.parse.urlencode({"__proto__[json spaces]": _INDENT}))

        after = client.get(url)
        polluted = became_indented(baseline.text, after.text)

        # Best-effort restore of the cosmetic property.
        for target in targets:
            client.request("POST", target, headers=hdrs, data=_pollute_body(0),
                           allow_redirects=False)

        if polluted:
            findings.append(
                Finding(
                    title="Server-side prototype pollution",
                    severity=Severity.HIGH,
                    target=result.target.host,
                    category="prototype-pollution",
                    location=url,
                    description=(
                        "Sending {\"__proto__\":{\"json spaces\":10}} changed the JSON "
                        "endpoint's output to pretty-printed, proving the server merges "
                        "attacker input into Object.prototype. Depending on gadgets this "
                        "can escalate to DoS or RCE."
                    ),
                    remediation="Reject/skip '__proto__', 'constructor', 'prototype' keys "
                    "during object merges; use Map or null-prototype objects.",
                    evidence="response formatting changed after __proto__ 'json spaces' pollution",
                    source=_SOURCE,
                    extra={"gadget": "json spaces"},
                )
            )
            break  # one confirmation is enough

    return findings
