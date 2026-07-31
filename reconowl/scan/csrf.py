"""Native check: missing anti-CSRF tokens on state-changing forms.

State-changing HTML forms (``method=post``) should carry an unpredictable
anti-CSRF token so a third-party site can't forge the request using the
victim's ambient session. The crawler already extracts every form's field
names (including hidden inputs), so a POST form whose fields contain no
token-like name is a candidate.

To keep false positives low, findings are gated on the site's cookie posture:
if session cookies are ``SameSite=Strict/Lax`` the browser already blocks
cross-site POSTs, so no finding is raised; without that protection the risk is
real and severity depends on whether cookie-based auth is in play.
"""

from __future__ import annotations

from ..models import Finding, ScanResult, Severity
from ..utils.net import in_scope

_SOURCE = "native:csrf"

# Substrings / exact names that indicate an anti-CSRF (or equivalent) token field.
_TOKEN_SUBSTRINGS = ("csrf", "xsrf", "nonce", "authenticity", "verificationtoken", "antiforgery")
_TOKEN_NAMES = {
    "_token", "token", "__requestverificationtoken", "csrfmiddlewaretoken",
    "authenticity_token", "anti-csrf", "_csrf_token",
}


def _has_csrf_token(params: list[str]) -> bool:
    for name in params:
        low = name.lower()
        if low in _TOKEN_NAMES:
            return True
        if any(sub in low for sub in _TOKEN_SUBSTRINGS):
            return True
    return False


def _cookie_posture(result: ScanResult, config, client) -> tuple[bool, bool]:
    """Return (uses_cookie_auth, samesite_protected) for the target."""
    raw = ""
    base = result.target.base_url
    if base:
        resp = client.get(base)
        raw = resp.header("set-cookie").lower()
    header_names = {k.lower() for k in config.build_headers()}
    uses_cookie = bool(raw) or "cookie" in header_names
    samesite = "samesite=strict" in raw or "samesite=lax" in raw
    return uses_cookie, samesite


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    if not getattr(config, "csrf_check", True):
        return []

    candidates = []
    seen: set[str] = set()
    for form in result.forms:
        if form.method.upper() != "POST":
            continue
        if not in_scope(form.url, result.target.host):
            continue
        if form.url in seen:
            continue
        if _has_csrf_token(form.params):
            continue
        seen.add(form.url)
        candidates.append(form)

    if not candidates:
        return []

    uses_cookie, samesite = _cookie_posture(result, config, client)
    if samesite:
        # The browser already blocks cross-site POSTs for these cookies.
        return []

    severity = Severity.MEDIUM if uses_cookie else Severity.LOW
    note = ("session cookies carry no SameSite=Strict/Lax protection"
            if uses_cookie else
            "no cookie-based session was observed, so impact depends on the app's auth")

    findings: list[Finding] = []
    for form in candidates[:12]:
        findings.append(Finding(
            title=f"POST form without anti-CSRF token: {form.url}",
            severity=severity,
            target=result.target.host,
            category="csrf",
            location=form.url,
            description=f"The POST form submitting to {form.url} contains no anti-CSRF "
            f"token field ({', '.join(form.params) or 'no named fields'}), and "
            f"{note}. An attacker page could forge this request using the victim's session.",
            remediation="Add a per-session unpredictable anti-CSRF token to state-changing "
            "forms and validate it server-side; set session cookies to SameSite=Lax/Strict.",
            evidence=f"POST {form.url} fields=[{', '.join(form.params)}]",
            source=_SOURCE,
            extra={"fields": form.params},
        ))

    if findings:
        ui.warn(f"CSRF: {len(findings)} form(s) without an anti-CSRF token")
    return findings
