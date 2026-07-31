"""Unit tests for the CORS and open-redirect checks (pure logic, no network)."""

from __future__ import annotations

from strix.models import Severity
from strix.scan import cors, redirect


# --- CORS ------------------------------------------------------------------ #
def test_cors_reflected_origin_with_credentials_is_high():
    origin = cors._ARBITRARY_ORIGIN
    f = cors.analyze("https://a.com", origin, "arbitrary", origin, True)
    assert f is not None and f.severity is Severity.HIGH
    assert f.category == "cors-reflect-origin"


def test_cors_reflected_origin_without_credentials_is_medium():
    origin = cors._ARBITRARY_ORIGIN
    f = cors.analyze("https://a.com", origin, "arbitrary", origin, False)
    assert f is not None and f.severity is Severity.MEDIUM


def test_cors_null_origin():
    f = cors.analyze("https://a.com", "null", "null", "null", True)
    assert f is not None and f.category == "cors-null-origin"
    assert f.severity is Severity.HIGH


def test_cors_wildcard_variants():
    plain = cors.analyze("https://a.com", "null", "null", "*", False)
    assert plain is not None and plain.severity is Severity.INFO
    creds = cors.analyze("https://a.com", "null", "null", "*", True)
    assert creds is not None and creds.severity is Severity.HIGH


def test_cors_safe_when_not_reflected():
    # Server echoes only its own trusted origin — not a finding.
    assert cors.analyze("https://a.com", cors._ARBITRARY_ORIGIN, "arbitrary",
                        "https://a.com", True) is None
    assert cors.analyze("https://a.com", "null", "null", "", False) is None


# --- Open redirect --------------------------------------------------------- #
def test_redirect_detect_header():
    assert redirect.detect(302, f"https://{redirect._MARK}/x", "") == "header"
    assert redirect.detect(301, f"//{redirect._MARK}/", "") == "header"


def test_redirect_detect_ignores_same_site_and_200():
    assert redirect.detect(302, "https://legit.example/dashboard", "") == ""
    assert redirect.detect(200, f"https://{redirect._MARK}/", "") == ""


def test_redirect_detect_meta_refresh():
    body = f'<meta http-equiv="refresh" content="0;url=https://{redirect._MARK}/">'
    assert redirect.detect(200, "", body) == "meta"


def test_redirect_set_param_replaces_and_adds():
    assert redirect._set_param("http://a.com/x?next=1", "next", "P") == "http://a.com/x?next=P"
    added = redirect._set_param("http://a.com/x", "url", "P")
    assert "url=P" in added


def test_redirect_candidates_pick_redirect_params_only():
    class R:
        urls = ["http://a.com/go?next=/home", "http://a.com/p?id=1"]
        class target:  # noqa: N801
            base_url = "http://a.com"
            host = "a.com"
    pairs = redirect._candidates(R, cap=50)
    params = {p for _, p in pairs}
    assert "next" in params      # redirect param picked from urls
    assert "id" not in params     # non-redirect param ignored
    assert "url" in params        # base-url active probe added
