"""Native check: Server-Side Request Forgery (SSRF).

Two complementary strategies:

1. **Out-of-band (OOB) confirmation** — Strix starts a small HTTP listener and
   injects a unique-token URL pointing back at it into URL-shaped parameters. If
   the target's server fetches it, our listener records the token: a *confirmed*
   SSRF. This needs the target to be able to reach the scanner (internal/lab
   engagements), and produces zero false positives.
2. **In-band signature detection** — inject well-known internal targets (cloud
   metadata endpoints, ``file:///etc/passwd``) and look for their fingerprints in
   the response. Confirms SSRF that echoes fetched content back.
"""

from __future__ import annotations

import re
import secrets
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope
from ._common import fetch_baselines as _baselines
from .redirect import _set_param

_SOURCE = "native:ssrf"

# Parameters that commonly carry a URL the server will fetch.
_SSRF_PARAMS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "path",
    "continue", "site", "html", "file", "document", "feed", "reference",
    "ref", "data", "proxy", "fetch", "load", "open", "image", "img",
    "imageurl", "image_url", "callback", "webhook", "target", "domain",
    "host", "port", "to", "out", "view", "next", "u",
}

# (payload, substring signatures, regex signature or None)
_INBAND = (
    (
        "http://169.254.169.254/latest/meta-data/",
        ("ami-id", "instance-id", "iam/", "public-keys", "local-hostname", "meta-data"),
        None,
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        ("computeMetadata", "service-accounts", "project"),
        None,
    ),
    ("file:///etc/passwd", (), r"root:.*:0:0:"),
)


def _looks_like_url(value: str) -> bool:
    v = value.strip().lower()
    return v.startswith(("http://", "https://", "//"))


def _local_ip() -> str:
    """Best-effort primary outbound IP of this host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class OOBListener:
    """A tiny HTTP server that records the paths (tokens) it is hit with."""

    def __init__(self, bind_host: str = "0.0.0.0", port: int = 0) -> None:
        self.hits: set[str] = set()
        self._lock = threading.Lock()
        listener = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: D401
                pass

            def do_GET(self):  # noqa: N802
                with listener._lock:
                    listener.hits.add(self.path.strip("/").split("?")[0])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        self._server = HTTPServer((bind_host, port), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def got(self, token: str) -> bool:
        with self._lock:
            return token in self.hits


def _candidates(result, cap: int) -> list[tuple[str, str]]:
    """(url, param) pairs where the param likely drives a server-side fetch."""
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
        for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in _SSRF_PARAMS or _looks_like_url(value):
                add(url, key)

    base = result.target.base_url
    if base:
        for param in ("url", "uri", "path", "dest", "fetch", "proxy"):
            add(base.rstrip("/") + "/", param)

    return out[:cap]


def _signature_match(text: str, subs: tuple[str, ...], regex: str | None) -> bool:
    low = text.lower()
    if any(s.lower() in low for s in subs):
        return True
    return bool(regex and re.search(regex, text))


def _oob_check(candidates, client, config, ui) -> tuple[list[Finding], set[tuple[str, str]]]:
    findings: list[Finding] = []
    confirmed: set[tuple[str, str]] = set()

    oob_host = config.oob_host or _local_ip()
    try:
        listener = OOBListener(port=config.oob_port)
    except OSError as exc:
        ui.warn(f"SSRF OOB listener could not start ({exc}); in-band only.")
        return findings, confirmed
    listener.start()
    ui.info(f"SSRF OOB listener on {oob_host}:{listener.port}")

    token_map: dict[str, tuple[str, str]] = {}
    try:
        for url, param in candidates:
            token = "strixssrf" + secrets.token_hex(4)
            token_map[token] = (url, param)
            payload = f"http://{oob_host}:{listener.port}/{token}"
            client.get(_set_param(url, param, payload), allow_redirects=False)
        time.sleep(3.0)  # allow slow server-side fetches to call back
        for token, (url, param) in token_map.items():
            if listener.got(token):
                confirmed.add((url, param))
                findings.append(
                    Finding(
                        title=f"SSRF confirmed (out-of-band) via '{param}'",
                        severity=Severity.CRITICAL,
                        target=None,  # set below
                        category="ssrf",
                        location=url,
                        description=(
                            f"The '{param}' parameter caused the server to make a "
                            "request to an attacker-controlled host (out-of-band "
                            "callback received). This is a confirmed SSRF."
                        ),
                        remediation="Enforce an allowlist of permitted hosts/schemes; "
                        "block internal ranges and link-local addresses.",
                        evidence=f"callback token {token} received",
                        source=_SOURCE,
                        extra={"parameter": param, "method": "oob"},
                    )
                )
    finally:
        listener.stop()
    return findings, confirmed


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = _candidates(result, cap=25)
    if not candidates:
        return []

    findings: list[Finding] = []
    confirmed: set[tuple[str, str]] = set()

    if getattr(config, "ssrf_oob", True):
        oob_findings, confirmed = _oob_check(candidates, client, config, ui)
        findings.extend(oob_findings)

    # In-band signature detection (skip pairs already confirmed via OOB).
    inband_candidates = [c for c in candidates if c not in confirmed]
    baseline_cache = _baselines(client, inband_candidates, config.concurrency)

    def inband_probe(candidate: tuple[str, str]) -> Finding | None:
        url, param = candidate
        base_text = baseline_cache.get(url, "").lower()
        for payload, subs, regex in _INBAND:
            resp = client.get(_set_param(url, param, payload), allow_redirects=False)
            if not resp.ok:
                continue
            if _signature_match(resp.text, subs, regex) and not _signature_match(base_text, subs, regex):
                return Finding(
                    title=f"SSRF via '{param}' (in-band: {payload.split('://')[0]})",
                    severity=Severity.HIGH,
                    target=result.target.host,
                    category="ssrf",
                    location=_set_param(url, param, payload),
                    description=(
                        f"Injecting an internal target into '{param}' returned "
                        "its content in the response, confirming the server "
                        "fetched an attacker-chosen resource (SSRF)."
                    ),
                    remediation="Allowlist permitted hosts/schemes; block internal "
                    "and link-local ranges; disable unused URL schemes (file://).",
                    evidence=f"payload={payload}",
                    source=_SOURCE,
                    extra={"parameter": param, "method": "in-band"},
                    proof=build_proof(resp),
                )
        return None

    for _c, finding in parallel_map(inband_probe, inband_candidates, workers=config.concurrency):
        if finding is not None:
            findings.append(finding)

    # Fill target host on OOB findings (needed it after construction).
    for f in findings:
        if f.target is None:
            f.target = result.target.host
    return findings
