"""Automated form login → captures a session for authenticated scanning.

Fetches the login page, locates the form containing a password field, fills in
the credentials while preserving hidden fields (CSRF tokens), submits it, and
returns the resulting session cookies. Those cookies are merged into the run
config so the crawler and every check run authenticated.
"""

from __future__ import annotations

import re
import urllib.parse

import requests
import urllib3

from ..config import ScanConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|select|textarea)\b[^>]*>", re.I)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)""", re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?\s*(get|post)""", re.I)

_USER_HINTS = ("user", "email", "login", "name", "account", "uid")
_LOGGED_IN_HINTS = ("logout", "log out", "sign out", "signout", "my account", "dashboard")


def _attr(tag: str, name: str) -> str:
    m = re.search(rf"""{name}\s*=\s*["']([^"']*)""", tag, re.I)
    return m.group(1) if m else ""


def parse_login_form(html: str, page_url: str) -> dict | None:
    """Return {action, method, fields, user_field, pass_field} for the login form."""
    for m in _FORM_RE.finditer(html or ""):
        tag = m.group(0)
        inputs = _INPUT_RE.findall(tag)
        fields: dict[str, str] = {}
        pass_field = ""
        user_field = ""
        for inp in inputs:
            name = _attr(inp, "name")
            if not name:
                continue
            itype = _attr(inp, "type").lower()
            fields[name] = _attr(inp, "value")
            if itype == "password" and not pass_field:
                pass_field = name
            elif itype in ("text", "email", "") and not user_field:
                if any(h in name.lower() for h in _USER_HINTS) or not user_field:
                    user_field = name
        if pass_field:
            return {
                "action": urllib.parse.urljoin(page_url, _ACTION_RE.search(tag).group(1) if _ACTION_RE.search(tag) else ""),
                "method": (_METHOD_RE.search(tag).group(1).upper() if _METHOD_RE.search(tag) else "POST"),
                "fields": fields,
                "user_field": user_field or "username",
                "pass_field": pass_field,
            }
    return None


def _looks_logged_in(text: str, login_check: str) -> bool:
    low = (text or "").lower()
    if login_check:
        return login_check.lower() in low
    if any(w in low for w in _LOGGED_IN_HINTS):
        return True
    # No password field left usually means we left the login page.
    return 'type="password"' not in low and "type='password'" not in low


def perform_login(config: ScanConfig, ui) -> dict[str, str] | None:
    """Log in and return the session cookies, or None on failure."""
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = config.user_agent
    for key, value in config.build_headers().items():
        session.headers[key] = value

    try:
        page = session.get(config.login_url, timeout=config.timeout)
    except requests.RequestException as exc:
        ui.warn(f"Login: could not load {config.login_url}: {exc}")
        return None

    form = parse_login_form(page.text, config.login_url)
    data: dict[str, str] = {}
    if form:
        data = dict(form["fields"])
        user_field = config.login_user_field or form["user_field"]
        pass_field = config.login_pass_field or form["pass_field"]
        action, method = form["action"], form["method"]
    else:
        # No HTML form — assume a POST login endpoint with given/guessed fields.
        user_field = config.login_user_field or "username"
        pass_field = config.login_pass_field or "password"
        action, method = config.login_url, "POST"

    data[user_field] = config.login_user
    data[pass_field] = config.login_pass
    ui.info(f"Login: submitting to {action} (user field '{user_field}')…")

    try:
        if method == "GET":
            resp = session.get(action, params=data, timeout=config.timeout)
        else:
            resp = session.post(action, data=data, timeout=config.timeout)
    except requests.RequestException as exc:
        ui.warn(f"Login: submission failed: {exc}")
        return None

    verify_text = resp.text
    if not _looks_logged_in(verify_text, config.login_check):
        # Re-check by loading the target base with the session.
        try:
            follow = session.get(resp.url, timeout=config.timeout)
            verify_text = follow.text
        except requests.RequestException:
            pass
    if not _looks_logged_in(verify_text, config.login_check):
        ui.warn("Login: could not confirm success (wrong creds or unknown success page).")
        return None

    cookies = session.cookies.get_dict()
    if not cookies:
        ui.warn("Login: succeeded but no session cookie was set.")
        return None
    ui.good(f"Login: authenticated, captured {len(cookies)} session cookie(s).")
    return cookies


def cookies_to_header(cookies: dict[str, str], existing: str = "") -> str:
    """Merge a cookie dict into a Cookie header string, keeping existing ones."""
    jar: dict[str, str] = {}
    for part in existing.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            jar[k.strip()] = v.strip()
    jar.update(cookies)
    return "; ".join(f"{k}={v}" for k, v in jar.items())
