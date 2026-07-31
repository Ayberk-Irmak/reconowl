"""Native check: CRLF injection / HTTP response splitting.

Injects a URL-encoded ``\\r\\n`` plus a unique marker header into parameters and
checks whether that header (or an injected cookie) appears in the *response
headers*. Because the marker is unique, a hit means the server genuinely let our
CRLF split its response — the basis for header injection, cache poisoning, and
response splitting. Detection reads headers, never the body, to avoid reflection
false positives.
"""

from __future__ import annotations

import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, HttpResponse, build_proof, in_scope

_SOURCE = "native:crlf"

_MARKER_HEADER = "x-reconowl-crlf"
_MARKER_VALUE = "reconowlcrlf1"

# URL-encoded CRLF payloads, including a couple of common filter bypasses.
_PAYLOADS = (
    f"crlf%0d%0a{_MARKER_HEADER}:%20{_MARKER_VALUE}",
    f"crlf%0D%0A{_MARKER_HEADER}:%20{_MARKER_VALUE}",
    f"crlf%0d%0aSet-Cookie:%20reconowlcrlf={_MARKER_VALUE}",
    # Unicode-encoded CRLF that some servers normalise to real \r\n.
    f"crlf%E5%98%8A%E5%98%8D{_MARKER_HEADER}:%20{_MARKER_VALUE}",
)

# Parameters most likely to be reflected into a header, tried first / on base URL.
_HEADER_PARAMS = (
    "url", "next", "redirect", "return", "dest", "goto", "r", "u", "lang",
    "page", "q", "search", "callback", "host",
)


def _inject(url: str, param: str, raw_value: str) -> str:
    """Set ``param`` to a pre-encoded ``raw_value`` without re-encoding it."""
    parts = urllib.parse.urlsplit(url)
    kept = [
        (k, v)
        for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if k != param
    ]
    encoded_kept = urllib.parse.urlencode(kept)
    injected = f"{param}={raw_value}"
    query = f"{encoded_kept}&{injected}" if encoded_kept else injected
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def detect(resp: HttpResponse) -> str:
    """Return "header"/"cookie" if our marker made it into the response headers."""
    for name, value in (resp.headers or {}).items():
        low_name = name.lower()
        low_val = str(value).lower()
        if low_name == _MARKER_HEADER and _MARKER_VALUE in low_val:
            return "header"
        if low_name == "set-cookie" and f"reconowlcrlf={_MARKER_VALUE}" in low_val:
            return "cookie"
    return ""


def _candidates(result, cap: int) -> list[tuple[str, str]]:
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
            add(url, key)

    base = result.target.base_url
    if base:
        for param in _HEADER_PARAMS:
            add(base.rstrip("/") + "/", param)

    return out[:cap]


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = _candidates(result, cap=30)
    if not candidates:
        return []

    def probe(candidate: tuple[str, str]) -> list[Finding]:
        url, param = candidate
        for payload in _PAYLOADS:
            resp = client.get(_inject(url, param, payload), allow_redirects=False)
            if not resp.ok:
                continue
            channel = detect(resp)
            if channel:
                return [Finding(
                    title=f"CRLF injection via parameter '{param}'",
                    severity=Severity.HIGH,
                    target=result.target.host,
                    category="crlf-injection",
                    location=_inject(url, param, payload),
                    description=(
                        f"A CRLF sequence in '{param}' was reflected into the "
                        f"response headers (injected {channel}), enabling HTTP "
                        "response splitting, header injection, and cache poisoning."
                    ),
                    remediation="Strip or reject CR/LF in user input before it "
                    "reaches response headers; use the framework's header API.",
                    evidence=f"payload={payload} -> injected {channel}",
                    source=_SOURCE,
                    extra={"parameter": param, "channel": channel},
                    proof=build_proof(resp),
                )]
        return []

    findings: list[Finding] = []
    for _c, found in parallel_map(probe, candidates, workers=config.concurrency):
        if found:
            findings.extend(found)
    return findings
