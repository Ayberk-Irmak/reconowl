"""Scan-to-scan diffing: compare findings between two Strix JSON reports.

Findings are matched by (category, location, title). The diff reports what is
**new**, what is **fixed** (present before, gone now), what **changed** (same
finding, different severity/CVSS), and what is unchanged — so repeat scans show
progress instead of a flat wall of findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


def load_report_findings(path: str) -> list[dict]:
    """Load the ``findings`` array from a Strix JSON report."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("findings", []) if isinstance(data, dict) else []


def _key(finding: dict) -> tuple[str, str, str]:
    return (
        finding.get("category", ""),
        finding.get("location") or finding.get("target", ""),
        finding.get("title", ""),
    )


def _cvss(finding: dict) -> float:
    return finding.get("cvss_score") or 0.0


@dataclass
class DiffResult:
    new: list[dict] = field(default_factory=list)
    fixed: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)  # {"finding","from","to"}
    unchanged: list[dict] = field(default_factory=list)
    old_total: int = 0
    new_total: int = 0

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "changed": len(self.changed),
            "unchanged": len(self.unchanged),
            "old_total": self.old_total,
            "new_total": self.new_total,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.counts(),
            "new": self.new,
            "fixed": self.fixed,
            "changed": self.changed,
        }


def diff_findings(old: list[dict], new: list[dict]) -> DiffResult:
    """Compute the diff between two findings lists."""
    old_map = {_key(f): f for f in old}
    new_map = {_key(f): f for f in new}
    old_keys, new_keys = set(old_map), set(new_map)

    result = DiffResult(old_total=len(old), new_total=len(new))
    result.new = sorted((new_map[k] for k in new_keys - old_keys), key=_cvss, reverse=True)
    result.fixed = sorted((old_map[k] for k in old_keys - new_keys), key=_cvss, reverse=True)

    for k in new_keys & old_keys:
        o, n = old_map[k], new_map[k]
        if o.get("severity") != n.get("severity") or _cvss(o) != _cvss(n):
            result.changed.append({
                "finding": n,
                "from": {"severity": o.get("severity"), "cvss": _cvss(o)},
                "to": {"severity": n.get("severity"), "cvss": _cvss(n)},
            })
        else:
            result.unchanged.append(n)
    return result


def write_json(diff: DiffResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(diff.to_dict(), fh, indent=2, ensure_ascii=False)


def render_markdown(diff: DiffResult, old_label: str, new_label: str) -> str:
    c = diff.counts()
    lines = [
        "# Strix scan diff",
        "",
        f"- **Baseline:** `{old_label}` ({c['old_total']} findings)",
        f"- **Current:** `{new_label}` ({c['new_total']} findings)",
        f"- **New:** {c['new']} · **Fixed:** {c['fixed']} · "
        f"**Changed:** {c['changed']} · **Unchanged:** {c['unchanged']}",
        "",
    ]

    def block(title: str, items: list[dict]) -> None:
        lines.append(f"## {title} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_None._")
            lines.append("")
            return
        for f in items:
            score = f.get("cvss_score")
            score_s = f" · CVSS {score:.1f}" if isinstance(score, (int, float)) else ""
            lines.append(f"- **[{f.get('severity')}]{score_s}** {f.get('title')} "
                         f"`{f.get('location', '')}`")
        lines.append("")

    block("🆕 New findings", diff.new)
    block("✅ Fixed findings", diff.fixed)
    if diff.changed:
        lines.append(f"## 🔀 Changed ({len(diff.changed)})")
        lines.append("")
        for ch in diff.changed:
            f = ch["finding"]
            lines.append(
                f"- **{f.get('title')}** `{f.get('location', '')}`: "
                f"{ch['from']['severity']} (CVSS {ch['from']['cvss']}) → "
                f"{ch['to']['severity']} (CVSS {ch['to']['cvss']})"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def write_markdown(diff: DiffResult, path: str, old_label: str, new_label: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(diff, old_label, new_label))
