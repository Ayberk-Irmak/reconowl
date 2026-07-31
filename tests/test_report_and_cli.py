"""Unit tests for report rendering and CLI target parsing (no network)."""

from __future__ import annotations

import json

from reconowl.cli import parse_target
from reconowl.models import Finding, Port, ScanResult, Severity, Target, WebEndpoint
from reconowl.report import html as html_report
from reconowl.report import json_report, markdown


def _sample() -> ScanResult:
    r = ScanResult(target=Target(raw="example.com", host="example.com", ip="1.2.3.4"))
    r.finished_at = "2026-01-01T00:00:00+00:00"
    r.ports.append(Port(number=443, service="https", product="nginx", version="1.24"))
    r.endpoints.append(WebEndpoint(url="https://example.com", status=200, title="Home", server="nginx"))
    r.subdomains = ["www.example.com", "api.example.com"]
    r.dns_records = {"A": ["1.2.3.4"]}
    r.tls = {"subject_cn": "example.com", "trusted": True, "days_to_expiry": 89}
    r.urls = ["https://example.com/p.php?id=1"]
    r.add_finding(Finding("SQLi candidate", Severity.HIGH, "example.com",
                          category="sqli", location="https://example.com/p.php?id=1'",
                          evidence="mysql error", remediation="use prepared statements"))
    r.add_finding(Finding("Missing CSP", Severity.MEDIUM, "example.com",
                          category="missing-header:csp", location="https://example.com"))
    return r


def test_parse_target_domain_url_ip():
    d = parse_target("example.com")
    assert d.host == "example.com" and not d.is_ip

    u = parse_target("https://example.com:8443/app")
    assert u.host == "example.com" and u.base_url == "https://example.com:8443"

    ip = parse_target("192.168.1.10")
    assert ip.is_ip and ip.ip == "192.168.1.10"


def test_json_report_roundtrip():
    r = _sample()
    data = json.loads(json_report.render(r))
    assert data["summary"]["total_findings"] == 2
    assert data["findings"][0]["severity"] == "High"  # sorted high-first
    assert data["ports"][0]["number"] == 443


def test_markdown_report_contains_findings():
    md = markdown.render(_sample())
    assert "# reconowl report" in md
    assert "SQLi candidate" in md
    assert "| High |" in md or "High" in md
    assert "443/tcp" in md


def test_html_report_renders_and_escapes():
    r = _sample()
    r.add_finding(Finding("<script>evil</script>", Severity.LOW, "example.com",
                          category="x", location="https://example.com"))
    out = html_report.render(r)
    assert "<!doctype html>" in out.lower()
    assert "reconowl" in out and "example.com" in out
    # user-controlled title must be escaped, not injected
    assert "<script>evil" not in out
    assert "&lt;script&gt;evil" in out
