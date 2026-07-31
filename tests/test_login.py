"""Unit tests for automated login parsing and helpers."""

from __future__ import annotations

from strix.recon import login


def test_parse_login_form_detects_fields_and_hidden():
    html = """
    <form action="/do-login" method="post">
      <input type="hidden" name="csrf" value="tok123">
      <input type="text" name="username">
      <input type="password" name="password">
      <button>go</button>
    </form>
    """
    form = login.parse_login_form(html, "https://a.com/login")
    assert form is not None
    assert form["action"] == "https://a.com/do-login"
    assert form["method"] == "POST"
    assert form["user_field"] == "username"
    assert form["pass_field"] == "password"
    assert form["fields"]["csrf"] == "tok123"  # CSRF preserved


def test_parse_login_form_email_field():
    html = '<form><input name="email" type="email"><input name="pw" type="password"></form>'
    form = login.parse_login_form(html, "https://a.com/login")
    assert form["user_field"] == "email" and form["pass_field"] == "pw"


def test_parse_login_form_none_without_password():
    html = '<form><input name="q" type="text"></form>'
    assert login.parse_login_form(html, "https://a.com") is None


def test_looks_logged_in():
    assert login._looks_logged_in("<a href=/logout>Logout</a>", "")
    assert login._looks_logged_in("Welcome to your Dashboard", "")
    assert login._looks_logged_in("secret area", "secret area")
    assert not login._looks_logged_in("secret area", "welcome admin")
    # still on a page with a password field -> not logged in
    assert not login._looks_logged_in('<input type="password">', "")


def test_cookies_to_header_merges():
    out = login.cookies_to_header({"session": "abc", "auth": "1"}, existing="theme=dark")
    parts = dict(p.strip().split("=", 1) for p in out.split(";"))
    assert parts["theme"] == "dark" and parts["session"] == "abc" and parts["auth"] == "1"
