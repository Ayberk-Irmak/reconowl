"""Unit tests for the CRLF injection check (pure logic, no network)."""

from __future__ import annotations

from reconowl.models import ScanResult, Target
from reconowl.scan import crlf
from reconowl.utils.net import HttpResponse


def _resp(headers):
    return HttpResponse(url="http://a", ok=True, status=302, headers=headers)


def test_detect_injected_header():
    resp = _resp({"Location": "x", "X-reconowl-CRLF": "reconowlcrlf1"})
    assert crlf.detect(resp) == "header"


def test_detect_injected_cookie():
    resp = _resp({"Set-Cookie": "reconowlcrlf=reconowlcrlf1; Path=/"})
    assert crlf.detect(resp) == "cookie"


def test_detect_negative():
    resp = _resp({"Location": "https://a.com/next", "Server": "nginx"})
    assert crlf.detect(resp) == ""


def test_inject_preserves_encoded_crlf():
    out = crlf._inject("http://a.com/p?id=1", "id", "crlf%0d%0aX:1")
    # The %0d%0a must NOT be re-encoded to %250d.
    assert "id=crlf%0d%0aX:1" in out
    assert "%250d" not in out


def test_inject_keeps_other_params():
    out = crlf._inject("http://a.com/p?a=1&b=2", "a", "P%0d%0a")
    assert "b=2" in out and "a=P%0d%0a" in out


def test_candidates_in_scope_and_base_probes():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/go?next=/x", "http://evil.com/go?next=/x"]
    pairs = crlf._candidates(r, cap=50)
    hosts = {u.split("/")[2] for u, _ in pairs}
    assert "evil.com" not in hosts           # out of scope excluded
    params = {p for _, p in pairs}
    assert "next" in params                  # from in-scope url
    assert "url" in params                   # from base-url header-param probes
