"""Unit tests for the exposed-services check."""

from __future__ import annotations

from reconowl.models import Port, ScanResult, Severity, Target, WebEndpoint
from reconowl.scan import exposed_services as es


def test_classify_port_database_high():
    label, sev, _ = es.classify_port(3306)
    assert "MySQL" in label and sev is Severity.HIGH


def test_classify_docker_critical():
    _, sev, _ = es.classify_port(2375)
    assert sev is Severity.CRITICAL


def test_classify_by_service_on_nonstandard_port():
    # MySQL running on an odd port is still caught via the service name.
    risk = es.classify_port(33060, "mysql")
    assert risk is not None and "MySQL" in risk[0]


def test_classify_unknown_port_none():
    assert es.classify_port(12321) is None


def test_check_flags_exposed_ports():
    r = ScanResult(target=Target(raw="t", host="t"))
    r.ports = [
        Port(number=3306, service="mysql", product="MySQL", version="8.0"),
        Port(number=21, service="ftp"),
        Port(number=8888, service="http"),  # not risky -> ignored
    ]
    findings = es.check(r, None, None, None)
    cats = [f.category for f in findings]
    assert cats.count("exposed-service") == 2
    mysql = next(f for f in findings if "MySQL" in f.title)
    assert mysql.severity is Severity.HIGH
    assert mysql.location == "t:3306"
    assert "8.0" in mysql.evidence


def test_check_flags_admin_panel_from_endpoint():
    r = ScanResult(target=Target(raw="t", host="t"))
    r.endpoints = [WebEndpoint(url="https://t:8443", status=200, title="Plesk Obsidian 18.0.79")]
    findings = es.check(r, None, None, None)
    panel = [f for f in findings if f.category == "exposed-panel"]
    assert panel and "Plesk" in panel[0].title
    assert panel[0].severity is Severity.MEDIUM
