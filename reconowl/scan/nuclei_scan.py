"""nuclei orchestration: run templates against discovered endpoints, parse JSONL."""

from __future__ import annotations

import json

from ..models import Finding, Severity
from ..utils.tools import find_tool, header_flags, run

_SOURCE = "nuclei"


def available() -> bool:
    return find_tool("nuclei") is not None


def _parse(text: str, host: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        sev = Severity.from_str(info.get("severity", "info"))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        findings.append(
            Finding(
                title=info.get("name", obj.get("template-id", "nuclei finding")),
                severity=sev,
                target=host,
                category=f"nuclei:{obj.get('template-id', 'unknown')}",
                location=obj.get("matched-at", obj.get("host", "")),
                description=info.get("description", "").strip(),
                remediation=(info.get("remediation") or "").strip(),
                evidence=obj.get("extracted-results", [""])[0] if obj.get("extracted-results") else "",
                source=_SOURCE,
                references=[r for r in refs if r],
                extra={
                    "template_id": obj.get("template-id", ""),
                    "tags": info.get("tags", []),
                    "cve": [t for t in (info.get("classification", {}) or {}).get("cve-id", []) or []],
                },
            )
        )
    return findings


def check(result, config, client, ui) -> list[Finding]:
    if not (config.use_external and config.run_nuclei and available()):
        return []
    targets = [e.url for e in result.endpoints] or ([result.target.base_url] if result.target.base_url else [])
    if not targets:
        return []

    ui.info(f"Running nuclei ({config.nuclei_severity()}) on {len(targets)} target(s)…")
    args = [
        "-silent", "-jsonl", "-no-color",
        "-severity", config.nuclei_severity(),
        "-timeout", "10",
        *header_flags(config.build_headers()),
        *config.nuclei_extra,
    ]
    code, out, err = run("nuclei", args, timeout=1800.0, input_text="\n".join(targets))
    result.tools_used["nuclei"] = "vulnerability templates"
    findings = _parse(out, result.target.host)
    ui.good(f"nuclei: {len(findings)} finding(s)")
    return findings
