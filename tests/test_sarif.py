"""Unit tests for SARIF 2.1.0 export."""

from __future__ import annotations

import json

from reconowl.models import Finding, ScanResult, Severity, Target
from reconowl.report import sarif
from reconowl.scoring import score_finding


def _result() -> ScanResult:
    r = ScanResult(target=Target(raw="example.com", host="example.com"))
    r.finished_at = "2026-01-01T00:00:00+00:00"
    for f in [
        Finding("SQLi", Severity.HIGH, "example.com", category="sqli",
                location="https://example.com/i.php?id=1'", description="sql error",
                remediation="use prepared statements"),
        Finding("Missing CSP", Severity.MEDIUM, "example.com",
                category="missing-header:content-security-policy",
                location="https://example.com"),
        Finding("robots.txt", Severity.INFO, "example.com", category="exposure",
                location="https://example.com/robots.txt"),
        Finding("SQLi", Severity.HIGH, "example.com", category="sqli",
                location="https://example.com/x.php?id=1'"),  # same rule, 2nd result
    ]:
        score_finding(f)
        r.add_finding(f)
    return r


def test_sarif_structure_and_levels():
    doc = json.loads(sarif.render(_result()))
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "reconowl"

    # One rule per unique category (sqli appears twice -> one rule).
    rule_ids = [r["id"] for r in driver["rules"]]
    assert rule_ids.count("sqli") == 1
    assert "missing-header:content-security-policy" in rule_ids

    results = doc["runs"][0]["results"]
    assert len(results) == 4  # one result per finding
    sqli_result = next(r for r in results if r["ruleId"] == "sqli")
    assert sqli_result["level"] == "error"  # High -> error
    assert any(r["level"] == "warning" for r in results)  # Medium -> warning
    assert any(r["level"] == "note" for r in results)     # Info -> note


def test_sarif_security_severity_from_cvss():
    doc = json.loads(sarif.render(_result()))
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["sqli"]["properties"]["security-severity"] == "9.8"


def test_sarif_result_location_and_ruleindex():
    doc = json.loads(sarif.render(_result()))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    for res in results:
        idx = res["ruleIndex"]
        assert rules[idx]["id"] == res["ruleId"]
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("https://example.com")


def test_rule_name_pascalcase():
    assert sarif._rule_name("missing-header:content-security-policy") == "MissingHeaderContentSecurityPolicy"
    assert sarif._rule_name("sqli") == "Sqli"
