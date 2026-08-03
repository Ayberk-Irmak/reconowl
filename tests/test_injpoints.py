"""Unit tests for the injection-point abstraction (GET/POST-form/JSON)."""

from __future__ import annotations

import json

from reconowl.models import Form, ScanResult, Target
from reconowl.scan import injpoints
from reconowl.utils.net import HttpResponse


class _CaptureClient:
    def __init__(self):
        self.calls = []

    def get(self, url, allow_redirects=True, **kw):
        self.calls.append(("GET", url, None, None))
        return HttpResponse(url=url, ok=True, status=200, headers={}, text="ok")

    def request(self, method, url, headers=None, data=None, allow_redirects=True):
        self.calls.append((method, url, headers, data))
        return HttpResponse(url=url, ok=True, status=200, headers={}, text="ok")


def test_build_query_and_form_points():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/p?id=1&x=2"]
    r.forms = [
        Form(url="http://a.com/login", method="POST", params=["user", "pass"]),
        Form(url="http://a.com/api/search", method="POST", params=["q"]),
    ]
    pts = injpoints.build(r, "a.com", cap=40)
    kinds = {(p.kind, p.param) for p in pts}
    assert ("query", "id") in kinds and ("query", "x") in kinds
    assert ("form", "user") in kinds and ("form", "pass") in kinds
    # /api/search POST also yields a JSON point
    assert ("json", "q") in kinds and ("form", "q") in kinds


def test_send_query_encodes():
    c = _CaptureClient()
    p = injpoints.InjectionPoint("GET", "http://a.com/p", "id", "query", {"id": "1", "x": "2"})
    injpoints.send(c, p, "1'")
    method, url, _h, _d = c.calls[-1]
    assert method == "GET" and "id=1%27" in url and "x=2" in url


def test_send_form_and_json_bodies():
    c = _CaptureClient()
    fp = injpoints.InjectionPoint("POST", "http://a.com/login", "user", "form", {"user": "1", "pass": "1"})
    injpoints.send(c, fp, "admin'")
    method, url, headers, data = c.calls[-1]
    assert method == "POST" and "urlencoded" in headers["Content-Type"]
    assert "user=admin%27" in data and "pass=1" in data

    jp = injpoints.InjectionPoint("POST", "http://a.com/api", "q", "json", {"q": "1"})
    injpoints.send(c, jp, "x'")
    _m, _u, headers, data = c.calls[-1]
    assert headers["Content-Type"] == "application/json"
    assert json.loads(data) == {"q": "x'"}


def test_send_json_value_nested_operator():
    c = _CaptureClient()
    jp = injpoints.InjectionPoint("POST", "http://a.com/api", "user", "json", {"user": "1", "pass": "1"})
    injpoints.send_json_value(c, jp, {"$ne": None})
    _m, _u, _h, data = c.calls[-1]
    assert json.loads(data) == {"user": {"$ne": None}, "pass": "1"}


def test_query_url_raw_preserves_encoding():
    p = injpoints.InjectionPoint("GET", "http://a.com/p", "f", "query", {"f": "1"})
    raw = injpoints._query_url(p, "..%2f..%2fetc", raw=True)
    assert "f=..%2f..%2fetc" in raw  # not double-encoded


def test_build_prioritizes_crawled_over_archive_urls():
    """Crawled/live URLs must beat harvested archive URLs for the injection cap."""
    from reconowl.models import ScanResult, Target
    from reconowl.scan import injpoints
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    # 50 archive URLs (with params) placed BEFORE the one crawled URL, like Wayback.
    r.urls = [f"https://a.com/arch{i}.php?x=1" for i in range(50)]
    live = "https://a.com/live.php?vuln=1"
    r.urls.append(live)
    r.crawled.add(live)
    points = injpoints.build(r, "a.com", cap=5)
    assert any(p.url == "https://a.com/live.php" and p.param == "vuln" for p in points), \
        "crawled URL was crowded out of the cap by archive URLs"
