"""Unit tests for scan-to-scan diffing."""

from __future__ import annotations

import json

from strix import diffing


def _f(cat, loc, title, sev="High", cvss=7.5):
    return {"category": cat, "location": loc, "title": title, "severity": sev, "cvss_score": cvss}


def test_diff_new_fixed_unchanged_changed():
    old = [
        _f("sqli", "u1", "SQLi"),
        _f("xss", "u2", "XSS", "Medium", 6.1),
        _f("lfi", "u3", "LFI"),                       # will be fixed
    ]
    new = [
        _f("sqli", "u1", "SQLi"),                     # unchanged
        _f("xss", "u2", "XSS", "High", 8.1),          # changed severity/cvss
        _f("ssrf", "u4", "SSRF", "High", 8.6),        # new
    ]
    dr = diffing.diff_findings(old, new)
    assert [f["title"] for f in dr.new] == ["SSRF"]
    assert [f["title"] for f in dr.fixed] == ["LFI"]
    assert len(dr.changed) == 1 and dr.changed[0]["finding"]["title"] == "XSS"
    assert len(dr.unchanged) == 1
    c = dr.counts()
    assert c == {"new": 1, "fixed": 1, "changed": 1, "unchanged": 1, "old_total": 3, "new_total": 3}


def test_new_and_fixed_sorted_by_cvss():
    old: list[dict] = []
    new = [_f("a", "u", "low", "Low", 3.1), _f("b", "u", "high", "Critical", 9.8)]
    dr = diffing.diff_findings(old, new)
    assert [f["title"] for f in dr.new] == ["high", "low"]  # highest CVSS first


def test_load_report_findings(tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"findings": [_f("sqli", "u", "SQLi")]}))
    findings = diffing.load_report_findings(str(p))
    assert findings[0]["title"] == "SQLi"


def test_render_markdown_sections():
    old = [_f("lfi", "u3", "LFI")]
    new = [_f("ssrf", "u4", "SSRF")]
    md = diffing.render_markdown(diffing.diff_findings(old, new), "old.json", "new.json")
    assert "# Strix scan diff" in md
    assert "New findings (1)" in md and "SSRF" in md
    assert "Fixed findings (1)" in md and "LFI" in md


def test_write_json(tmp_path):
    dr = diffing.diff_findings([], [_f("ssrf", "u", "SSRF")])
    out = tmp_path / "diff.json"
    diffing.write_json(dr, str(out))
    data = json.loads(out.read_text())
    assert data["summary"]["new"] == 1
    assert data["new"][0]["title"] == "SSRF"
