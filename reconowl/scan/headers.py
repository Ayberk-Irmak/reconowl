"""Native checks: security headers, cookie flags, and version disclosure."""

from __future__ import annotations

from ..models import Finding, Severity
from ..utils.net import HttpClient, HttpResponse

_SOURCE = "native:headers"

# header -> (finding title, severity, remediation)
_SECURITY_HEADERS = {
    "strict-transport-security": (
        "Missing HSTS header",
        Severity.MEDIUM,
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "over HTTPS to force secure transport.",
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy",
        Severity.MEDIUM,
        "Define a Content-Security-Policy to mitigate XSS and data injection.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options / frame-ancestors",
        Severity.LOW,
        "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' to prevent "
        "clickjacking.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options",
        Severity.LOW,
        "Set 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy",
        Severity.INFO,
        "Set a Referrer-Policy (e.g. 'strict-origin-when-cross-origin').",
    ),
}


def _cookie_findings(url: str, set_cookies: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        flags = []
        if "secure" not in low:
            flags.append("Secure")
        if "httponly" not in low:
            flags.append("HttpOnly")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            findings.append(
                Finding(
                    title=f"Cookie '{name}' missing {', '.join(flags)} flag(s)",
                    severity=Severity.LOW,
                    target=url,
                    category="cookie-flags",
                    location=url,
                    description=(
                        f"The cookie '{name}' is set without the "
                        f"{', '.join(flags)} attribute(s), weakening its "
                        "protection against theft or CSRF."
                    ),
                    remediation="Set Secure, HttpOnly, and SameSite on sensitive cookies.",
                    evidence=raw[:200],
                    source=_SOURCE,
                )
            )
    return findings


def analyze(url: str, resp: HttpResponse) -> list[Finding]:
    """Turn one endpoint's headers into findings."""
    findings: list[Finding] = []
    if not resp.ok:
        return findings

    is_https = url.lower().startswith("https")
    present = {k.lower() for k in (resp.headers or {})}

    for header, (title, severity, remediation) in _SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not is_https:
            continue  # HSTS only meaningful over HTTPS
        if header not in present:
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    target=url,
                    category=f"missing-header:{header}",
                    location=url,
                    description=f"Response from {url} does not set the '{header}' header.",
                    remediation=remediation,
                    source=_SOURCE,
                )
            )

    # Version / tech disclosure
    for disclosing in ("server", "x-powered-by", "x-aspnet-version"):
        value = resp.header(disclosing)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                Finding(
                    title=f"Version disclosure via '{disclosing}'",
                    severity=Severity.INFO,
                    target=url,
                    category="version-disclosure",
                    location=url,
                    description=f"The '{disclosing}' header reveals '{value}'.",
                    remediation="Suppress or genericise version banners.",
                    evidence=f"{disclosing}: {value}",
                    source=_SOURCE,
                )
            )

    # Cookies
    set_cookie = resp.header("set-cookie")
    if set_cookie:
        findings.extend(_cookie_findings(url, [set_cookie]))

    return findings


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    """Analyze headers for every probed endpoint."""
    findings: list[Finding] = []
    seen: set[str] = set()
    targets = [e.url for e in result.endpoints] or ([result.target.base_url] if result.target.base_url else [])
    for url in targets:
        if url in seen:
            continue
        seen.add(url)
        resp = client.get(url)
        findings.extend(analyze(url, resp))
    return findings
