"""SARIF 2.1.0 export for CI / GitHub code-scanning integration.

Each finding becomes a SARIF ``result``; each finding category becomes a
``rule``. The CVSS score is exposed as the ``security-severity`` rule property
(GitHub reads this to rank alerts), and reconowl severity maps to the SARIF level.
"""

from __future__ import annotations

import json
import re

from .. import __version__
from ..models import ScanResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_HOMEPAGE = "https://github.com/Ayberk-Irmak/reconowl"

_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
    "None": "none",
}


def _rule_name(category: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", category)
    return "".join(p[:1].upper() + p[1:] for p in parts if p) or "Finding"


def _level_for(label: str) -> str:
    return _LEVEL.get(label, "note")


def _build_rule(finding) -> dict:
    help_text = finding.remediation or finding.description or ""
    return {
        "id": finding.category,
        "name": _rule_name(finding.category),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {"text": help_text},
        "helpUri": finding.references[0] if finding.references else _HOMEPAGE,
        "defaultConfiguration": {"level": _level_for(finding.severity.label)},
        "properties": {
            "security-severity": f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "0.0",
            "tags": ["security", finding.source],
        },
    }


def _build_result(finding, rule_index: int) -> dict:
    uri = finding.location or finding.target or ""
    message = finding.description or finding.title
    if finding.location:
        message = f"{message} (at {finding.location})"
    return {
        "ruleId": finding.category,
        "ruleIndex": rule_index,
        "level": _level_for(finding.severity.label),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "severity": finding.severity.label,
            "cvss": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "evidence": finding.evidence,
        },
    }


def render(result: ScanResult) -> str:
    findings = result.sorted_findings()
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for f in findings:
        if f.category not in rule_index:
            rule_index[f.category] = len(rules)
            rules.append(_build_rule(f))

    results = [_build_result(f, rule_index[f.category]) for f in findings]

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reconowl",
                        "version": __version__,
                        "informationUri": _HOMEPAGE,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": result.target.raw},
                "results": results,
                "properties": {
                    "target": result.target.to_dict(),
                    "started_at": result.started_at,
                    "finished_at": result.finished_at,
                    "max_cvss": result.max_cvss(),
                },
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def write(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
