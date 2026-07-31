"""Native check: CORS misconfiguration.

Sends crafted ``Origin`` headers and inspects the ``Access-Control-Allow-Origin``
(ACAO) and ``Access-Control-Allow-Credentials`` (ACAC) response headers. The
dangerous cases are: reflecting an arbitrary origin, trusting the ``null``
origin, or a wildcard — each markedly worse when credentials are also allowed.
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..utils.net import HttpClient, build_proof

_SOURCE = "native:cors"

# A distinctive attacker-controlled origin, and the special "null" origin.
_ARBITRARY_ORIGIN = "https://strix-cors-probe.example"
_ORIGINS = ((_ARBITRARY_ORIGIN, "arbitrary"), ("null", "null"))


def analyze(url: str, origin: str, kind: str, acao: str, acac: bool) -> Finding | None:
    """Classify one CORS response. ``acac`` is Access-Control-Allow-Credentials."""
    if not acao:
        return None
    acao = acao.strip()
    low = acao.lower()

    if low == "*":
        if acac:
            return Finding(
                title="CORS wildcard with credentials",
                severity=Severity.HIGH,
                target=url,
                category="cors-wildcard-credentials",
                location=url,
                description=(
                    "The server returns 'Access-Control-Allow-Origin: *' together "
                    "with 'Access-Control-Allow-Credentials: true'. This is an "
                    "insecure combination that exposes credentialed responses."
                ),
                remediation="Never combine a wildcard ACAO with credentials; echo "
                "only explicitly allowlisted origins.",
                evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: true",
                source=_SOURCE,
            )
        return Finding(
            title="Wildcard CORS policy (Access-Control-Allow-Origin: *)",
            severity=Severity.INFO,
            target=url,
            category="cors-wildcard",
            location=url,
            description="The endpoint allows any origin to read its responses.",
            remediation="Restrict ACAO to trusted origins if the data is not public.",
            evidence=f"ACAO: {acao}",
            source=_SOURCE,
        )

    if kind == "arbitrary" and acao == origin:
        return Finding(
            title="CORS reflects arbitrary Origin" + (" with credentials" if acac else ""),
            severity=Severity.HIGH if acac else Severity.MEDIUM,
            target=url,
            category="cors-reflect-origin",
            location=url,
            description=(
                "The server reflects any supplied Origin into "
                "Access-Control-Allow-Origin"
                + (", and allows credentials — any site can read authenticated "
                   "responses." if acac else ", letting any site read its responses.")
            ),
            remediation="Validate Origin against a strict allowlist; do not reflect it.",
            evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: {str(acac).lower()}",
            source=_SOURCE,
        )

    if kind == "null" and low == "null":
        return Finding(
            title="CORS allows 'null' Origin" + (" with credentials" if acac else ""),
            severity=Severity.HIGH if acac else Severity.MEDIUM,
            target=url,
            category="cors-null-origin",
            location=url,
            description=(
                "The server trusts the 'null' origin, which an attacker can force "
                "via a sandboxed iframe or data: document"
                + (" — combined with credentials this is directly exploitable." if acac else ".")
            ),
            remediation="Do not treat 'null' as a trusted origin.",
            evidence=f"Origin: null -> ACAO: {acao}, ACAC: {str(acac).lower()}",
            source=_SOURCE,
        )

    return None


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
        for origin, kind in _ORIGINS:
            resp = client.get(url, headers={"Origin": origin})
            if not resp.ok:
                continue
            acao = resp.header("access-control-allow-origin")
            acac = resp.header("access-control-allow-credentials").strip().lower() == "true"
            finding = analyze(url, origin, kind, acao, acac)
            if finding is not None:
                finding.proof = build_proof(resp)
                findings.append(finding)
    return findings
