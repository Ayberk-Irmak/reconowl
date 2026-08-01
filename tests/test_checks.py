"""Unit tests for native checks: header analysis and injection helpers."""

from __future__ import annotations

from reconowl.models import Severity
from reconowl.scan import headers, injection
from reconowl.utils.net import HttpResponse, in_scope


def _resp(url, hdrs, status=200):
    return HttpResponse(url=url, ok=True, status=status, headers=hdrs, text="<html></html>")


def test_headers_flags_missing_security_headers():
    resp = _resp("https://a.com", {"Server": "nginx/1.24.0"})
    findings = headers.analyze("https://a.com", resp)
    cats = {f.category for f in findings}
    assert "missing-header:strict-transport-security" in cats
    assert "missing-header:content-security-policy" in cats
    assert "version-disclosure" in cats


def test_headers_hsts_skipped_on_http():
    resp = _resp("http://a.com", {})
    cats = {f.category for f in headers.analyze("http://a.com", resp)}
    # HSTS only meaningful over https
    assert "missing-header:strict-transport-security" not in cats
    assert "missing-header:content-security-policy" in cats


def test_headers_all_present_no_findings():
    resp = _resp(
        "https://a.com",
        {
            "Strict-Transport-Security": "max-age=1",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Server": "server",
        },
    )
    assert headers.analyze("https://a.com", resp) == []


def test_cookie_flag_findings():
    resp = _resp("https://a.com", {"Set-Cookie": "sid=abc; Path=/"})
    findings = headers.analyze("https://a.com", resp)
    cookie = [f for f in findings if f.category == "cookie-flags"]
    assert cookie and cookie[0].severity is Severity.LOW
    assert "Secure" in cookie[0].title


def test_injection_parametrized_dedupes_by_shape():
    urls = [
        "http://a.com/p.php?id=1",
        "http://a.com/p.php?id=2",       # same shape -> dropped
        "http://a.com/q.php?cat=1&id=2",
        "http://a.com/static.html",      # no params -> dropped
    ]
    picked = injection._parametrized(urls, cap=10)
    assert picked == ["http://a.com/p.php?id=1", "http://a.com/q.php?cat=1&id=2"]


def test_injection_mutate_only_target_param():
    out = injection._mutate("http://a.com/p.php?id=1&cat=2", "id", "'")
    assert "id=1%27" in out
    assert "cat=2" in out


def test_sql_error_signatures_cover_sqlite_and_classic_engines():
    # A Python/SQLite debug leak (as a vulnerable app emits) must be recognised —
    # this was a real gap fixed after end-to-end testing on a vulnerable target.
    sqlite_leak = 'sqlite3.OperationalError: unrecognized token: "\'"'.lower()
    assert any(sig in sqlite_leak for sig in injection._SQL_ERRORS)
    # Classic MySQL/Postgres error leaks stay covered.
    assert any(sig in "you have an error in your sql syntax" for sig in injection._SQL_ERRORS)
    assert any(sig in "syntax error at or near \"'\"" for sig in injection._SQL_ERRORS)


def test_in_scope_keeps_target_and_siblings_rejects_others():
    assert in_scope("https://shop.example.com/x", "example.com") is True
    assert in_scope("https://example.com/x", "shop.example.com") is True
    assert in_scope("https://api.example.com/x", "shop.example.com") is True
    assert in_scope("http://127.0.0.1:80/x", "example.com") is False
    assert in_scope("https://evil.com/x", "example.com") is False


def test_apex_domain_handles_multi_label_suffixes():
    from reconowl.utils.net import apex_domain
    assert apex_domain("insuyu.com.tr") == "insuyu.com.tr"
    assert apex_domain("www.insuyu.com.tr") == "insuyu.com.tr"
    assert apex_domain("bbc.co.uk") == "bbc.co.uk"
    assert apex_domain("a.b.example.com") == "example.com"
    assert apex_domain("example.com") == "example.com"


def test_in_scope_respects_multi_label_suffix():
    # A sibling under the real registrable domain is in scope…
    assert in_scope("https://www.insuyu.com.tr/x", "insuyu.com.tr") is True
    # …but an unrelated domain sharing only the public suffix is NOT.
    assert in_scope("https://evil.com.tr/x", "insuyu.com.tr") is False
