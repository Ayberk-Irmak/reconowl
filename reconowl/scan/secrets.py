"""Native check: hard-coded secrets found in JavaScript (from JS analysis)."""

from __future__ import annotations

from ..models import Finding, ScanResult, Severity

_SOURCE = "native:secrets"


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    findings: list[Finding] = []
    for hit in result.secrets:
        severity = Severity.from_str(hit.get("severity", "Low"))
        findings.append(
            Finding(
                title=f"Hard-coded secret in JavaScript: {hit['type']}",
                severity=severity,
                target=result.target.host,
                category="exposed-secret",
                location=hit.get("location", ""),
                description=(
                    f"A {hit['type']} appears hard-coded in client-side JavaScript, "
                    "where anyone can read it."
                ),
                remediation="Move secrets server-side, rotate the exposed credential, "
                "and never ship keys in client bundles.",
                evidence=f"{hit['type']}: {hit['match']}",
                source=_SOURCE,
                extra={"type": hit["type"]},
            )
        )
    return findings
