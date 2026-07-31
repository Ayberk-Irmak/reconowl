"""Unit tests for the SSTI check."""

from __future__ import annotations

from strix.models import ScanResult, Target
from strix.scan import ssti
from strix.utils.net import HttpResponse


def test_detect_evaluated_product():
    payload = "{{1009*1013}}"
    # Evaluated: product present, literal payload gone -> SSTI.
    assert ssti.detect("Hello 1022117!", payload) is True
    # Reflected only: literal payload still present -> not SSTI.
    assert ssti.detect(f"Hello {payload}", payload) is False
    # Product absent -> not SSTI.
    assert ssti.detect("Hello world", payload) is False


def test_detect_ignores_product_already_in_baseline():
    payload = "{{1009*1013}}"
    assert ssti.detect("x 1022117 y", payload, baseline="1022117 was here") is False


def test_product_is_distinctive():
    assert ssti._PRODUCT == "1022117"
    assert ssti._EXPR == "1009*1013"


def test_candidates_in_scope_and_base_probes():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/p?name=x", "http://evil.com/p?name=x"]
    pairs = ssti._candidates(r, cap=50)
    assert not any("evil.com" in u for u, _ in pairs)
    params = {p for _, p in pairs}
    assert "name" in params  # from in-scope url and base probes


def test_check_detects_ssti():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))

    class Client:
        def get(self, url, allow_redirects=True, **kwargs):
            # Simulate a template engine: if a {{A*B}} expression is present,
            # render the product; the baseline (no payload) has neither.
            if "1009%2A1013" in url or "1009*1013" in url:
                return HttpResponse(url=url, ok=True, status=200, headers={},
                                    text="<h1>Hello 1022117</h1>")
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="<h1>Hello </h1>")

    class UI:
        def info(self, m): pass

    from strix.config import ScanConfig
    findings = ssti.check(r, ScanConfig(), Client(), UI())
    assert findings and findings[0].category == "ssti"
    assert findings[0].severity.name == "HIGH"
