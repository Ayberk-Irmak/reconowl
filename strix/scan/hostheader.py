"""Native check: Host-header injection.

Sends requests with a bogus ``Host`` / ``X-Forwarded-Host`` and checks whether
the application trusts it — reflecting the attacker-controlled host into a
redirect ``Location`` (password-reset poisoning) or into absolute URLs in the
body (web-cache poisoning). A unique marker keeps false positives near zero: it
can only appear if the server actually echoed our header.
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..utils.net import HttpClient, build_proof

_SOURCE = "native:host-header"
_MARK = "strix-hhi-probe.example"
_HEADERS = ("Host", "X-Forwarded-Host")


def _host_of(location: str) -> str:
    import urllib.parse

    loc = location.strip()
    if loc.startswith("//"):
        loc = "http:" + loc
    try:
        return urllib.parse.urlsplit(loc).netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def analyze(url: str, header: str, location: str, body: str, mark: str = _MARK) -> str:
    """Return the reflection channel ("redirect"/"body") if ``mark`` is trusted."""
    if location and _host_of(location) == mark:
        return "redirect"
    if body and (f"://{mark}" in body or f"//{mark}" in body):
        return "body"
    return ""


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    targets = [e.url for e in result.endpoints] or (
        [result.target.base_url] if result.target.base_url else []
    )
    findings: list[Finding] = []
    seen: set[str] = set()
    for url in targets:
        if url in seen:
            continue
        seen.add(url)
        for header in _HEADERS:
            resp = client.get(url, headers={header: _MARK}, allow_redirects=False)
            if not resp.ok:
                continue
            channel = analyze(url, header, resp.header("location"), resp.text)
            if channel:
                findings.append(
                    Finding(
                        title=f"Host-header injection via '{header}' ({channel})",
                        severity=Severity.MEDIUM,
                        target=result.target.host,
                        category="host-header-injection",
                        location=url,
                        description=(
                            f"The server reflects an attacker-supplied '{header}' "
                            f"header into the {channel}. This enables web-cache "
                            "poisoning and password-reset link poisoning."
                        ),
                        remediation="Validate Host against an allowlist of expected "
                        "domains; do not build absolute URLs from the Host header.",
                        evidence=f"{header}: {_MARK} -> reflected in {channel}",
                        source=_SOURCE,
                        extra={"header": header, "channel": channel},
                        proof=build_proof(resp),
                    )
                )
                break  # one channel per endpoint is enough
    return findings
