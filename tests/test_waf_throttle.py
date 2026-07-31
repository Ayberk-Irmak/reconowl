"""Unit tests for adaptive throttling and WAF detection."""

from __future__ import annotations

from strix.config import ScanConfig
from strix.models import ScanResult, Target
from strix.scan import waf
from strix.utils.net import HttpClient, HttpResponse


def test_classify_outcomes():
    assert HttpClient._classify(200, True) == "ok"
    assert HttpClient._classify(429, True) == "block"
    assert HttpClient._classify(403, True) == "block"
    assert HttpClient._classify(None, False) == "error"


def test_adaptive_backoff_triggers_on_block_spike():
    c = HttpClient(adaptive=True)
    assert c._min_interval == 0.0
    for _ in range(25):  # fill the window with blocks
        c._record("block")
    assert c.was_throttled is True
    assert c._min_interval >= 0.4


def test_gives_up_after_sustained_blocking():
    c = HttpClient(adaptive=True)
    for _ in range(25 * 4):  # four backoff windows of blocks
        c._record("block")
    assert c.gave_up is True
    # once given up, requests are fast-skipped without hitting the network
    resp = c.request("GET", "http://127.0.0.1:1/x")
    assert resp.ok is False and "blocking" in resp.error


def test_adaptive_disabled_does_nothing():
    c = HttpClient(adaptive=False)
    for _ in range(30):
        c._record("block")
    assert c.was_throttled is False


def test_no_backoff_when_mostly_ok():
    c = HttpClient(adaptive=True)
    for i in range(25):
        c._record("block" if i < 5 else "ok")  # 20% bad
    assert c.was_throttled is False


def test_waf_fingerprint_from_headers():
    assert waf._fingerprint({"CF-RAY": "abc", "Server": "cloudflare"}, "") == "cloudflare"
    assert waf._fingerprint({"X-Sucuri-ID": "1"}, "") == "Sucuri"
    assert waf._fingerprint({}, "Request blocked by mod_security") == "ModSecurity"
    assert waf._fingerprint({"Server": "nginx"}, "hello") == ""


def test_waf_check_behavioural():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))

    class Cfg:
        use_external = False

    class Client:
        def get(self, url, **k):
            if "strixwaf" in url:  # malicious probe blocked
                return HttpResponse(url=url, ok=True, status=403, headers={}, text="blocked")
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="ok")

    class UI:
        def warn(self, m): pass

    findings = waf.check(r, Cfg(), Client(), UI())
    assert findings and findings[0].category == "waf-detected"
    assert r.waf
