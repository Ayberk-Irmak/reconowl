"""Engine time-budget behaviour: truncation must be recorded, not silent."""

from __future__ import annotations

from strix.config import ScanConfig
from strix.models import Port, ScanResult, Target, WebEndpoint
from strix.scan import engine
from strix.utils.net import HttpResponse


class _Client:
    # reachable is decided from result.endpoints, so .get is never called here.
    def get(self, *a, **k):  # pragma: no cover - safety net
        raise AssertionError("network should not be hit in this test")


class _UI:
    def warn(self, m): pass
    def good(self, m): pass
    def info(self, m): pass
    def finding(self, *a, **k): pass


def test_time_budget_truncation_is_recorded(monkeypatch):
    monkeypatch.setattr(engine, "build_client", lambda cfg, timeout=None: _Client())
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    r.endpoints.append(WebEndpoint(url="https://a.com"))  # makes _web_reachable True offline
    cfg = ScanConfig(target="a.com", max_scan_seconds=0.0)  # deadline already passed

    engine.run(r, cfg, _UI())

    incomplete = [e for e in r.errors if "scan incomplete" in e]
    assert incomplete, "truncation must be recorded in result.errors"
    # The very first native check must be named among the skipped ones.
    assert engine._NATIVE_CHECKS[0][0] in incomplete[0]


class _DeadClient:
    def get(self, *a, **k):
        return HttpResponse(url="x", ok=False, error="blocked")


def test_web_unreachable_with_open_ports_records_likely_block(monkeypatch):
    monkeypatch.setattr(engine, "build_client", lambda cfg, timeout=None: _DeadClient())
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    r.ports.append(Port(number=443, state="open", service="https"))  # port open, web dead
    engine.run(r, ScanConfig(target="a.com"), _UI())
    blocked = [e for e in r.errors if "blocked/rate-limited" in e]
    assert blocked, "open web port + dead HTTP must be reported as a likely block"


def test_directory_bruteforce_runs_after_injection_checks():
    names = [n for n, _ in engine._NATIVE_CHECKS]
    assert names[-1] == "Directory brute-force"
    assert names.index("Injection probes") < names.index("Directory brute-force")
    assert names.index("Default credentials") < names.index("Directory brute-force")
