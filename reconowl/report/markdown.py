"""Markdown report — readable in a terminal, on GitHub, or in notes."""

from __future__ import annotations

from ..models import ScanResult, Severity
from .summary import build_summary


def render(result: ScanResult) -> str:
    t = result.target
    lines: list[str] = []
    lines.append(f"# reconowl report — {t.host or t.raw}")
    lines.append("")
    lines.append(f"- **Target:** `{t.raw}`")
    if t.ip:
        lines.append(f"- **IP:** `{t.ip}`")
    lines.append(f"- **Started:** {result.started_at}")
    lines.append(f"- **Finished:** {result.finished_at}")
    if result.tools_used:
        lines.append(f"- **Tools used:** {', '.join(sorted(result.tools_used))}")
    lines.append("")

    # Executive summary
    summary = build_summary(result)
    lines.append("## Executive summary")
    lines.append("")
    lines.append(summary["narrative"])
    lines.append("")

    # Scan coverage
    cov = summary["coverage"]
    lines.append("## Scan coverage")
    lines.append("")
    if cov["complete"]:
        lines.append("✅ **Complete** — all applicable checks ran to completion.")
    else:
        lines.append("⚠️ **Partial** — the scan did not fully cover everything. "
                     "Findings are valid, but the *absence* of findings is inconclusive "
                     "for the items below:")
        lines.append("")
        for c in cov["caveats"]:
            lines.append(f"- {c}")
    lines.append("")

    # Summary
    counts = result.severity_counts()
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in reversed(Severity):
        lines.append(f"| {sev.label} | {counts[sev.label]} |")
    lines.append("")
    lines.append(f"**Highest CVSS:** {result.max_cvss():.1f}")
    lines.append("")
    lines.append(
        f"Assets: {len(result.subdomains)} subdomains, {len(result.ports)} open ports, "
        f"{len(result.endpoints)} web endpoints, {len(result.urls)} URLs."
    )
    lines.append("")

    # Findings
    lines.append("## Findings")
    lines.append("")
    findings = result.sorted_findings()
    if not findings:
        lines.append("_No findings._")
    for f in findings:
        lines.append(f"### [{f.severity.label}] {f.title}")
        lines.append("")
        if f.cvss_score is not None:
            lines.append(f"- **CVSS:** {f.cvss_score:.1f} ({f.cvss_severity}) `{f.cvss_vector}`")
        if f.location:
            lines.append(f"- **Location:** `{f.location}`")
        lines.append(f"- **Category:** `{f.category}`  ·  **Source:** `{f.source}`")
        if f.description:
            lines.append(f"- **Description:** {f.description}")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence}`")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        for ref in f.references:
            lines.append(f"- **Reference:** {ref}")
        if f.proof.get("request"):
            lines.append("")
            lines.append("<details><summary>Proof — request / response</summary>")
            lines.append("")
            lines.append("```http")
            lines.append(f.proof["request"])
            lines.append("")
            lines.append(f.proof.get("response", ""))
            lines.append("```")
            lines.append("")
            lines.append("</details>")
        lines.append("")

    # Recon appendix
    lines.append("## Reconnaissance")
    lines.append("")
    if result.ports:
        lines.append("### Open ports")
        lines.append("")
        lines.append("| Port | Service | Product | Version |")
        lines.append("|---|---|---|---|")
        for p in result.ports:
            lines.append(f"| {p.number}/{p.protocol} | {p.service} | {p.product} | {p.version} |")
        lines.append("")
    if result.subdomains:
        lines.append("### Subdomains")
        lines.append("")
        for s in result.subdomains:
            lines.append(f"- {s}")
        lines.append("")
    if result.dns_records:
        lines.append("### DNS records")
        lines.append("")
        for rtype, values in result.dns_records.items():
            lines.append(f"- **{rtype}:** {', '.join(values)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def write(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
