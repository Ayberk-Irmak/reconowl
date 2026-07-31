"""Unit tests for CVSS v3.1 scoring."""

from __future__ import annotations

from strix import scoring
from strix.models import Finding, Severity


def test_reference_base_scores():
    # Well-known CVSS v3.1 reference results.
    assert scoring.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (9.8, "Critical")
    assert scoring.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == (7.5, "High")
    assert scoring.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == (6.1, "Medium")
    assert scoring.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == (0.0, "None")


def test_severity_label_bands():
    assert scoring.severity_label(0.0) == "None"
    assert scoring.severity_label(3.9) == "Low"
    assert scoring.severity_label(4.0) == "Medium"
    assert scoring.severity_label(6.9) == "Medium"
    assert scoring.severity_label(7.0) == "High"
    assert scoring.severity_label(9.0) == "Critical"


def test_vector_for_exact_prefix_and_fallback():
    exact = Finding("x", Severity.HIGH, "h", category="sqli")
    assert scoring.vector_for(exact) == scoring._CATEGORY_VECTORS["sqli"]

    prefix = Finding("x", Severity.LOW, "h", category="missing-header:csp")
    assert scoring.vector_for(prefix) == scoring._PREFIX_VECTORS["missing-header:"]

    # nuclei findings ignore prefix map and use severity fallback
    nuc = Finding("x", Severity.CRITICAL, "h", category="nuclei:CVE-2021-1")
    assert scoring.vector_for(nuc) == scoring._SEVERITY_FALLBACK[Severity.CRITICAL]


def test_score_finding_sets_fields():
    f = Finding("Cmd inj", Severity.CRITICAL, "h", category="command-injection")
    scoring.score_finding(f)
    assert f.cvss_score == 9.8
    assert f.cvss_severity == "Critical"
    assert f.cvss_vector.startswith("CVSS:3.1/")


def test_apply_scores_all():
    fs = [
        Finding("a", Severity.HIGH, "h", category="xxe"),
        Finding("b", Severity.INFO, "h", category="graphql-endpoint"),
    ]
    scoring.apply(fs)
    assert fs[0].cvss_score == 7.5
    assert fs[1].cvss_score == 0.0
