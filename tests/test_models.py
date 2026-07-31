"""Unit tests for the core data model."""

from __future__ import annotations

from reconowl.models import Finding, Port, ScanResult, Severity, Target


def test_severity_ordering_and_parse():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.from_str("high") is Severity.HIGH
    assert Severity.from_str("CRITICAL") is Severity.CRITICAL
    assert Severity.from_str("bogus") is Severity.INFO
    assert Severity.HIGH.label == "High"


def test_finding_dedup_and_dict():
    f1 = Finding("Missing HSTS", Severity.MEDIUM, "h", category="missing-header:hsts", location="u")
    f2 = Finding("Missing HSTS", Severity.MEDIUM, "h", category="missing-header:hsts", location="u")
    assert f1.dedup_key() == f2.dedup_key()
    d = f1.to_dict()
    assert d["severity"] == "Medium"
    assert d["title"] == "Missing HSTS"


def test_scanresult_counts_and_sorting():
    r = ScanResult(target=Target(raw="x", host="x"))
    r.add_finding(Finding("a", Severity.LOW, "x"))
    r.add_finding(Finding("b", Severity.CRITICAL, "x"))
    r.add_finding(Finding("c", Severity.MEDIUM, "x"))
    counts = r.severity_counts()
    assert counts["Critical"] == 1 and counts["Low"] == 1 and counts["Medium"] == 1
    order = [f.severity for f in r.sorted_findings()]
    assert order == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_scanresult_to_dict_shape():
    r = ScanResult(target=Target(raw="x", host="x", ip="1.2.3.4"))
    r.ports.append(Port(number=80, service="http"))
    r.add_finding(Finding("f", Severity.HIGH, "x"))
    d = r.to_dict()
    assert d["tool"] == "reconowl"
    assert d["summary"]["total_findings"] == 1
    assert d["ports"][0]["number"] == 80
    assert d["findings"][0]["severity"] == "High"
