"""Unit tests for subdomain deepening orchestration (no real network)."""

from __future__ import annotations

from reconowl import subscan
from reconowl.config import ScanConfig
from reconowl.models import Finding, ScanResult, Severity, Target, WebEndpoint
from reconowl.utils.net import HttpResponse


class _FakeClient:
    """Answers only for an allowlisted set of base URLs."""

    def __init__(self, live_bases):
        self.live = set(live_bases)

    def get(self, url, allow_redirects=True, **kwargs):
        if url in self.live:
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="ok")
        return HttpResponse(url=url, ok=False, error="unreachable")


def test_live_subdomains_filters_dead():
    client = _FakeClient(["https://a.example.com", "http://b.example.com"])
    live = subscan._live_subdomains(
        ["a.example.com", "b.example.com", "dead.example.com"], client, workers=4
    )
    assert live == {"a.example.com": "https://a.example.com", "b.example.com": "http://b.example.com"}


def test_merge_dedupes_endpoints_and_findings():
    main = ScanResult(target=Target(raw="x.com", host="x.com"))
    main.endpoints.append(WebEndpoint(url="https://x.com", status=200))
    main.add_finding(Finding("A", Severity.LOW, "x.com", category="c", location="https://x.com"))

    sub = ScanResult(target=Target(raw="a.x.com", host="a.x.com"))
    sub.endpoints.append(WebEndpoint(url="https://a.x.com", status=200))
    sub.endpoints.append(WebEndpoint(url="https://x.com", status=200))  # dup
    sub.add_finding(Finding("B", Severity.HIGH, "a.x.com", category="c", location="https://a.x.com"))
    sub.add_finding(Finding("A", Severity.LOW, "x.com", category="c", location="https://x.com"))  # dup
    sub.technologies = ["nginx"]

    subscan._merge(main, sub)
    assert len(main.endpoints) == 2  # dup dropped
    titles = sorted(f.title for f in main.findings)
    assert titles == ["A", "B"]  # dup A not re-added
    assert main.technologies == ["nginx"]


def test_run_scans_live_subdomains(monkeypatch):
    result = ScanResult(target=Target(raw="x.com", host="x.com"))
    result.subdomains = ["a.x.com", "b.x.com", "x.com"]  # x.com is the primary, skipped

    monkeypatch.setattr(
        subscan, "_live_subdomains",
        lambda subs, client, workers: {"a.x.com": "https://a.x.com"},
    )
    monkeypatch.setattr(subscan.dnsx, "resolve_ip", lambda h, **k: "1.2.3.4")

    scanned = []

    def fake_active_run(sub_result, config, ui, web_only=False):
        assert web_only is True
        sub_result.endpoints.append(WebEndpoint(url=sub_result.target.base_url, status=200))

    def fake_engine_run(sub_result, config, ui):
        scanned.append(sub_result.target.host)
        sub_result.add_finding(
            Finding("Missing CSP", Severity.MEDIUM, sub_result.target.host,
                    category="missing-header:csp", location=sub_result.target.base_url)
        )

    monkeypatch.setattr(subscan.active, "run", fake_active_run)
    monkeypatch.setattr(subscan.engine, "run", fake_engine_run)

    ui = subscan._QuietUI(type("U", (), {"warn": lambda *a: None, "error": lambda *a: None,
                                         "finding": lambda *a, **k: None, "info": lambda *a: None,
                                         "good": lambda *a: None})())
    subscan.run(result, ScanConfig(max_subdomains=25), ui)

    assert scanned == ["a.x.com"]  # only the live, non-primary subdomain
    assert any(f.location == "https://a.x.com" for f in result.findings)
    assert any(e.url == "https://a.x.com" for e in result.endpoints)
