"""Native check: open redirect.

Sets an off-site payload into parameters that commonly drive redirects and, for
the base URL, probes the usual redirect parameter names. A finding is raised only
when the server actually redirects (3xx Location, or a meta-refresh) to the
attacker-controlled host — not merely reflecting it in the body.
"""

from __future__ import annotations

import re
import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope

_SOURCE = "native:redirect"

# Parameter names frequently used to control redirection.
_REDIRECT_PARAMS = {
    "url", "next", "redirect", "redir", "return", "returnurl", "return_url",
    "returnto", "return_to", "dest", "destination", "goto", "continue",
    "target", "to", "rurl", "u", "r", "link", "out", "redirect_uri",
    "redirecturl", "forward", "checkout_url", "image_url", "callback",
}

# A distinctive host we can detect in a Location header (never actually visited).
_MARK = "strix-redirect-probe.example"
_PAYLOADS = (f"https://{_MARK}/", f"//{_MARK}/", f"https:/{_MARK}")

_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=([^"'>\s]+)""", re.I
)


def _host_of(location: str) -> str:
    loc = location.strip()
    if loc.startswith("//"):
        loc = "http:" + loc
    elif loc.startswith(("/\\", "\\/")):
        loc = "http://" + loc[2:]
    try:
        return urllib.parse.urlsplit(loc).netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def detect(status: int | None, location: str, body: str, mark: str = _MARK) -> str:
    """Return the redirect mechanism ("header"/"meta") if it targets ``mark``."""
    if status and 300 <= status < 400 and location:
        if _host_of(location) == mark:
            return "header"
    if body:
        m = _META_REFRESH.search(body)
        if m and _host_of(m.group(1)) == mark:
            return "meta"
    return ""


def _set_param(url: str, param: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if any(k == param for k, _ in pairs):
        pairs = [(k, value if k == param else v) for k, v in pairs]
    else:
        pairs.append((param, value))
    query = urllib.parse.urlencode(pairs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _candidates(result, cap: int) -> list[tuple[str, str]]:
    """Distinct (url, redirect-param) pairs to test, deduped by shape."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(url: str, param: str) -> None:
        parts = urllib.parse.urlsplit(url)
        key = (parts.netloc, parts.path, param)
        if key not in seen:
            seen.add(key)
            out.append((url, param))

    for url in result.urls:
        if not in_scope(url, result.target.host):
            continue
        parts = urllib.parse.urlsplit(url)
        for key, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in _REDIRECT_PARAMS:
                add(url, key)

    base = result.target.base_url
    if base:
        for param in ("next", "url", "redirect", "return", "dest", "r"):
            add(base.rstrip("/") + "/", param)

    return out[:cap]


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = _candidates(result, cap=50)
    if not candidates:
        return []

    def probe(candidate: tuple[str, str]) -> list[Finding]:
        url, param = candidate
        for payload in _PAYLOADS:
            test_url = _set_param(url, param, payload)
            resp = client.get(test_url, allow_redirects=False)
            if not resp.ok:
                continue
            mechanism = detect(resp.status, resp.header("location"), resp.text)
            if mechanism:
                return [Finding(
                    title=f"Open redirect via parameter '{param}'",
                    severity=Severity.MEDIUM,
                    target=result.target.host,
                    category="open-redirect",
                    location=test_url,
                    description=(
                        f"The '{param}' parameter controls a {mechanism}-based "
                        "redirect to an externally-supplied URL, enabling "
                        "phishing and OAuth token theft."
                    ),
                    remediation="Allowlist redirect destinations or use relative "
                    "paths / indirection tokens instead of raw URLs.",
                    evidence=f"payload={payload} -> Location: {resp.header('location')}",
                    source=_SOURCE,
                    extra={"parameter": param, "mechanism": mechanism},
                    proof=build_proof(resp),
                )]
        return []

    findings: list[Finding] = []
    for _c, found in parallel_map(probe, candidates, workers=config.concurrency):
        if found:
            findings.extend(found)
    return findings
