"""Unit tests for the broken-access-control / IDOR check."""

from __future__ import annotations

from strix.config import ScanConfig
from strix.models import ScanResult, Severity, Target
from strix.scan import access_control as ac
from strix.utils.net import HttpResponse


def test_helpers():
    assert ac.is_login_page('<input type="password">')
    assert not ac.is_login_page("<html>dashboard</html>")
    assert ac.similar("x" * 1000, "x" * 1050)
    assert not ac.similar("x" * 1000, "x" * 500)
    assert ac.is_sensitive("http://a/account/settings")
    assert ac.is_sensitive("http://a/view?id=5")
    assert not ac.is_sensitive("http://a/about")
    assert ac._int_id_params("http://a/x?id=7&q=hi") == [("id", 7)]


def test_unauth_check_flags_missing_control():
    r = ScanResult(target=Target(raw="a.com", host="a.com"))
    r.urls = ["http://a.com/account?id=1"]
    cfg = ScanConfig(cookie="session=abc")  # authenticated

    class AuthedClient:  # session present -> protected page returns content
        def get(self, url, **k):
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="Account details " * 40)

    # The bare (unauth) client returns the SAME content -> no access control.
    import strix.scan.access_control as mod
    mod._bare_client = lambda config: AuthedClient()

    findings = ac._unauth_check(r, cfg, AuthedClient(), None)
    assert findings and findings[0].category == "broken-access-control"
    assert findings[0].severity is Severity.HIGH


def test_unauth_check_no_flag_when_login_required():
    r = ScanResult(target=Target(raw="a.com", host="a.com"))
    r.urls = ["http://a.com/account?id=1"]
    cfg = ScanConfig(cookie="session=abc")

    class Authed:
        def get(self, url, **k):
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="Account details " * 40)

    class Bare:  # unauth returns a login page -> properly protected
        def get(self, url, **k):
            return HttpResponse(url=url, ok=True, status=200, headers={}, text='<input type="password">')

    import strix.scan.access_control as mod
    mod._bare_client = lambda config: Bare()
    assert ac._unauth_check(r, cfg, Authed(), None) == []


def test_idor_tamper_flags_different_object():
    r = ScanResult(target=Target(raw="a.com", host="a.com"))
    r.urls = ["http://a.com/invoice?id=2"]

    class Client:
        def get(self, url, **k):
            # id=2 -> "invoice two", id=1 -> "invoice one" (different, same shape)
            body = "Invoice number one, total $100 " * 5 if "id=1" in url else "Invoice number two, total $200 " * 5
            return HttpResponse(url=url, ok=True, status=200, headers={}, text=body)

    findings = ac._idor_tamper_check(r, ScanConfig(), Client(), None)
    assert findings and findings[0].category == "idor"
    assert "id" == findings[0].extra["parameter"]


def test_idor_tamper_no_flag_on_identical_or_error():
    r = ScanResult(target=Target(raw="a.com", host="a.com"))
    r.urls = ["http://a.com/invoice?id=2"]

    class Same:
        def get(self, url, **k):
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="static page " * 20)

    assert ac._idor_tamper_check(r, ScanConfig(), Same(), None) == []
