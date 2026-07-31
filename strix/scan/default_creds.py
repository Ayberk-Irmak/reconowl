"""Native check: default / weak credentials.

Tries a *small, conservative* set of well-known credential pairs against:

- **HTTP Basic Auth** realms (a 401 that becomes 200 with credentials is a
  definitive hit), and
- **login forms** (submitting each pair with CSRF/hidden fields preserved, and
  comparing to a known-bad baseline to avoid false positives).

The list is intentionally short to avoid account lockouts — this flags obvious
defaults, it is not a brute-forcer.
"""

from __future__ import annotations

import base64
import urllib.parse

import requests
import urllib3

from ..models import Finding, ScanResult, Severity
from ..recon import login as _login
from ..utils.net import in_scope

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SOURCE = "native:default-creds"

# Conservative, high-signal defaults (kept small to avoid lockouts).
_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "changeme"),
    ("admin", ""),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]

_LOGIN_PATHS = (
    "login", "admin", "admin/login", "administrator", "user/login", "signin",
    "wp-login.php", "panel", "manager/html",
)


def _session(config) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = config.user_agent
    return s


# --------------------------------------------------------------------------- #
# HTTP Basic Auth
# --------------------------------------------------------------------------- #
def _basic_targets(result: ScanResult, config, client) -> list[str]:
    base = result.target.base_url
    urls: list[str] = []
    seen: set[str] = set()

    def add(u: str) -> None:
        if u not in seen and in_scope(u, result.target.host):
            seen.add(u)
            urls.append(u)

    if base:
        add(base)
        for p in _LOGIN_PATHS:
            add(urllib.parse.urljoin(base + "/", p))
    for e in result.endpoints:
        add(e.url)

    targets = []
    for u in urls[:12]:
        resp = client.get(u, allow_redirects=False)
        if resp.status == 401 and "basic" in resp.header("www-authenticate").lower():
            targets.append(u)
    return targets


def _basic_auth_check(result, config, client, ui) -> list[Finding]:
    findings: list[Finding] = []
    for url in _basic_targets(result, config, client):
        for user, pw in _CREDS:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            resp = client.get(url, headers={"Authorization": f"Basic {token}"}, allow_redirects=False)
            if resp.ok and resp.status not in (401, 403):
                findings.append(Finding(
                    title=f"Default HTTP Basic Auth credentials ({user}:{pw or '<blank>'})",
                    severity=Severity.CRITICAL,
                    target=result.target.host,
                    category="default-credentials",
                    location=url,
                    description=f"The Basic-Auth realm at {url} accepts the default "
                    f"credentials '{user}:{pw}', granting access.",
                    remediation="Change default credentials and enforce a strong password policy.",
                    evidence=f"401 -> {resp.status} with {user}:{pw or '<blank>'}",
                    source=_SOURCE,
                    extra={"user": user, "auth": "basic"},
                ))
                break
    return findings


# --------------------------------------------------------------------------- #
# Login forms
# --------------------------------------------------------------------------- #
def _login_targets(result: ScanResult, config, client) -> list[tuple[str, dict]]:
    base = result.target.base_url
    urls: list[str] = []
    seen: set[str] = set()

    def add(u: str) -> None:
        if u not in seen and in_scope(u, result.target.host):
            seen.add(u)
            urls.append(u)

    if config.login_url:
        add(config.login_url)
    if base:
        for p in _LOGIN_PATHS:
            add(urllib.parse.urljoin(base + "/", p))
    for u in result.urls:
        if any(k in u.lower() for k in ("login", "signin", "admin")):
            add(u)

    targets: list[tuple[str, dict]] = []
    for u in urls[:8]:
        resp = client.get(u)
        if not resp.ok:
            continue
        form = _login.parse_login_form(resp.text, u)
        if form:
            targets.append((u, form))
        if len(targets) >= 3:
            break
    return targets


def _attempt(config, login_url: str, form: dict, user: str, pw: str):
    """Submit a login form with one credential pair (fresh session, CSRF-aware)."""
    session = _session(config)
    try:
        page = session.get(login_url, timeout=config.timeout)
        cur = _login.parse_login_form(page.text, login_url) or form
        data = dict(cur.get("fields", {}))
        data[config.login_user_field or cur["user_field"]] = user
        data[config.login_pass_field or cur["pass_field"]] = pw
        action, method = cur["action"], cur["method"]
        if method == "GET":
            resp = session.get(action, params=data, timeout=config.timeout)
        else:
            resp = session.post(action, data=data, timeout=config.timeout)
        return resp.status_code, resp.text
    except requests.RequestException:
        return None, ""


def login_success(fail_text: str, resp_text: str) -> bool:
    """True if a response looks logged-in while the known-bad attempt did not."""
    return _login._looks_logged_in(resp_text, "") and not _login._looks_logged_in(fail_text, "")


def _login_form_check(result, config, client, ui) -> list[Finding]:
    findings: list[Finding] = []
    for url, form in _login_targets(result, config, client):
        # Establish the "wrong credentials" response as a baseline.
        _s, fail_text = _attempt(config, url, form, "strix-nouser-x9", "strix-nopass-x9")
        for user, pw in _CREDS:
            status, text = _attempt(config, url, form, user, pw)
            if status is None:
                continue
            if login_success(fail_text, text):
                findings.append(Finding(
                    title=f"Default login credentials ({user}:{pw or '<blank>'})",
                    severity=Severity.CRITICAL,
                    target=result.target.host,
                    category="default-credentials",
                    location=url,
                    description=f"The login form at {url} accepts the default credentials "
                    f"'{user}:{pw}', granting authenticated access.",
                    remediation="Change default credentials, enforce a strong password "
                    "policy, and add rate-limiting / MFA.",
                    evidence=f"login succeeded with {user}:{pw or '<blank>'}",
                    source=_SOURCE,
                    extra={"user": user, "auth": "form"},
                ))
                break  # one confirmed pair per form is enough
    return findings


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    if not getattr(config, "default_creds", True):
        return []
    findings = _basic_auth_check(result, config, client, ui)
    findings += _login_form_check(result, config, client, ui)
    if findings:
        ui.good(f"Default credentials: {len(findings)} hit(s)")
    return findings
