"""Tests for the executive summary + scan-coverage assessment."""

from __future__ import annotations

from reconowl.models import Finding, ScanResult, Severity, Target
from reconowl.report.summary import build_summary
from reconowl.scan.exposures import _exposure_category
from reconowl.scoring import score_finding


def _result_with_findings():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    for t, sev, cat in [("SQLi", Severity.HIGH, "sqli"),
                        ("Missing CSP", Severity.MEDIUM, "missing-header:csp")]:
        f = Finding(t, sev, "a.com", category=cat, location="https://a.com")
        score_finding(f)
        r.add_finding(f)
    return r


def test_summary_complete_when_no_incomplete_errors():
    s = build_summary(_result_with_findings())
    assert s["coverage"]["complete"] is True
    assert s["coverage"]["caveats"] == []
    assert "reported 2 finding" in s["narrative"]
    assert s["top_findings"][0]["title"] == "SQLi"  # highest severity first


def test_summary_flags_partial_coverage_from_errors():
    r = _result_with_findings()
    r.errors.append("scan incomplete: time budget (900s) reached, 3 check(s) skipped: SSRF")
    s = build_summary(r)
    assert s["coverage"]["complete"] is False
    assert any("skipped" in c.lower() for c in s["coverage"]["caveats"])
    assert "partial" in s["narrative"].lower() or "inconclusive" in s["narrative"].lower()
    assert "partial coverage" in s["headline"]


def test_summary_no_findings():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    s = build_summary(r)
    assert "no findings" in s["narrative"].lower()
    assert s["coverage"]["complete"] is True


def test_exposure_category_matches_severity():
    assert _exposure_category(Severity.HIGH) == "exposure"        # 7.5
    assert _exposure_category(Severity.MEDIUM) == "sensitive-file"  # 5.4
    assert _exposure_category(Severity.LOW) == "sensitive-file"     # 3.1
    assert _exposure_category(Severity.INFO) == "info-file"         # 0.0
