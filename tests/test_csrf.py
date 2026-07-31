"""Unit tests for the CSRF (missing anti-CSRF token) check."""

from __future__ import annotations

from reconowl.config import ScanConfig
from reconowl.models import Form, ScanResult, Target
from reconowl.scan import csrf
from reconowl.utils.net import HttpResponse


class _UI:
    def warn(self, m): pass
    def good(self, m): pass


def _result(forms):
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    r.forms = forms
    return r


def _client(set_cookie: str = ""):
    class Client:
        def get(self, url, **k):
            hdrs = {"Set-Cookie": set_cookie} if set_cookie else {}
            return HttpResponse(url=url, ok=True, status=200, headers=hdrs, text="ok")
    return Client()


def test_token_detection():
    assert csrf._has_csrf_token(["amount", "_csrf"]) is True
    assert csrf._has_csrf_token(["csrfmiddlewaretoken", "x"]) is True
    assert csrf._has_csrf_token(["__RequestVerificationToken"]) is True
    assert csrf._has_csrf_token(["body", "note"]) is False


def test_flags_post_form_without_token():
    r = _result([Form(url="https://a.com/comment", method="POST", params=["body"])])
    findings = csrf.check(r, ScanConfig(target="a.com"), _client("sid=1; Path=/"), _UI())
    assert len(findings) == 1
    assert findings[0].category == "csrf"
    assert findings[0].severity.name == "MEDIUM"  # cookie present, no SameSite


def test_ignores_form_with_token():
    r = _result([Form(url="https://a.com/x", method="POST", params=["body", "_csrf"])])
    assert csrf.check(r, ScanConfig(target="a.com"), _client("sid=1"), _UI()) == []


def test_ignores_get_forms():
    r = _result([Form(url="https://a.com/search", method="GET", params=["q"])])
    assert csrf.check(r, ScanConfig(target="a.com"), _client("sid=1"), _UI()) == []


def test_samesite_suppresses_finding():
    r = _result([Form(url="https://a.com/comment", method="POST", params=["body"])])
    client = _client("sid=1; SameSite=Lax; Path=/")
    assert csrf.check(r, ScanConfig(target="a.com"), client, _UI()) == []


def test_low_severity_without_cookies():
    r = _result([Form(url="https://a.com/comment", method="POST", params=["body"])])
    findings = csrf.check(r, ScanConfig(target="a.com"), _client(""), _UI())
    assert findings and findings[0].severity.name == "LOW"


def test_out_of_scope_form_skipped():
    r = _result([Form(url="https://evil.com/x", method="POST", params=["body"])])
    assert csrf.check(r, ScanConfig(target="a.com"), _client("sid=1"), _UI()) == []


def test_disabled_via_config():
    r = _result([Form(url="https://a.com/x", method="POST", params=["body"])])
    assert csrf.check(r, ScanConfig(target="a.com", csrf_check=False), _client("sid=1"), _UI()) == []
