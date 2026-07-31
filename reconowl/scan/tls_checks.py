"""TLS findings derived from the certificate facts gathered in active recon."""

from __future__ import annotations

from ..models import Finding, Severity

_SOURCE = "native:tls"
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check(result, config, client, ui) -> list[Finding]:
    tls = result.tls
    if not tls or tls.get("error"):
        return []

    host = result.target.host
    loc = f"{host}:443"
    findings: list[Finding] = []

    if tls.get("expired"):
        findings.append(
            Finding(
                title="Expired TLS certificate",
                severity=Severity.HIGH,
                target=host,
                category="tls-expired",
                location=loc,
                description=f"The certificate expired on {tls.get('not_after')}.",
                remediation="Renew the certificate immediately.",
                evidence=f"days_to_expiry={tls.get('days_to_expiry')}",
                source=_SOURCE,
            )
        )
    elif isinstance(tls.get("days_to_expiry"), int) and tls["days_to_expiry"] < 21:
        findings.append(
            Finding(
                title="TLS certificate expiring soon",
                severity=Severity.LOW,
                target=host,
                category="tls-expiring",
                location=loc,
                description=f"The certificate expires in {tls['days_to_expiry']} days.",
                remediation="Renew before expiry to avoid an outage.",
                source=_SOURCE,
            )
        )

    if tls.get("self_signed"):
        findings.append(
            Finding(
                title="Self-signed TLS certificate",
                severity=Severity.MEDIUM,
                target=host,
                category="tls-self-signed",
                location=loc,
                description="The certificate is self-signed and not issued by a trusted CA.",
                remediation="Use a certificate from a trusted CA (e.g. Let's Encrypt).",
                source=_SOURCE,
            )
        )
    elif tls.get("trusted") is False and not tls.get("expired"):
        findings.append(
            Finding(
                title="Untrusted TLS certificate",
                severity=Severity.MEDIUM,
                target=host,
                category="tls-untrusted",
                location=loc,
                description=f"Certificate did not validate: {tls.get('verify_error', 'unknown')}.",
                remediation="Fix the chain / hostname so the certificate validates.",
                evidence=tls.get("verify_error", ""),
                source=_SOURCE,
            )
        )

    protocol = tls.get("protocol", "")
    if protocol in _WEAK_PROTOCOLS:
        findings.append(
            Finding(
                title=f"Weak TLS protocol negotiated ({protocol})",
                severity=Severity.MEDIUM,
                target=host,
                category="tls-weak-protocol",
                location=loc,
                description=f"The server negotiated {protocol}, which is deprecated.",
                remediation="Disable TLS 1.1 and below; require TLS 1.2+.",
                source=_SOURCE,
            )
        )

    return findings
