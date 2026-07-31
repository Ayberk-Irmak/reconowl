"""Native check: broken access control (BAC) and IDOR.

Three strategies, from strongest signal to heuristic:

1. **Unauthenticated access** (when a session is configured) — re-request
   sensitive discovered resources with no session; if the protected content
   comes back anyway, access control is missing.
2. **Cross-user access** (when ``--second-cookie`` is given) — fetch an
   ID-bearing resource as a second user; if they see the first user's object,
   that's confirmed IDOR.
3. **ID tampering** — change a numeric identifier; if a *different* valid object
   of the same shape is returned, that's a likely IDOR to verify manually.
"""

from __future__ import annotations

import re
import urllib.parse

from ..models import Finding, ScanResult, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope
from .redirect import _set_param

_SOURCE = "native:access-control"

_SENSITIVE_PATH = re.compile(
    r"(admin|account|profile|dashboard|settings|/user|users|private|manage|"
    r"edit|delete|order|invoice|billing|/api/|/me\b|config|upload|download|"
    r"report|internal|/edit|/update)", re.I,
)
_ID_PARAMS = {
    "id", "uid", "user", "user_id", "userid", "account", "acct", "pid", "oid",
    "order", "order_id", "invoice", "doc", "docid", "file", "fileid", "num",
    "record", "ref", "item", "itemid", "cid", "gid", "nid", "key",
}
_LOGIN_RE = re.compile(r"""(type=["']?password|name=["']?password|sign\s*in|log\s*in)""", re.I)


def is_login_page(text: str) -> bool:
    return bool(_LOGIN_RE.search(text or ""))


def similar(a: str, b: str, tol: float = 0.15) -> bool:
    la, lb = len(a or ""), len(b or "")
    longest = max(la, lb, 1)
    return abs(la - lb) / longest <= tol


def is_sensitive(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    if _SENSITIVE_PATH.search(parts.path):
        return True
    return any(k.lower() in _ID_PARAMS for k, _ in urllib.parse.parse_qsl(parts.query))


def _int_id_params(url: str) -> list[tuple[str, int]]:
    out = []
    for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True):
        if v.isdigit():
            out.append((k, int(v)))
    return out


def _bare_client(config) -> HttpClient:
    return HttpClient(timeout=min(config.timeout, 8.0), user_agent=config.user_agent,
                      rate_limit=config.rate_limit)


def _unauth_check(result, config, client, ui) -> list[Finding]:
    if not config.is_authenticated():
        return []
    host = result.target.host
    urls = [u for u in dict.fromkeys(result.urls) if in_scope(u, host) and is_sensitive(u)][:30]
    if not urls:
        return []
    bare = _bare_client(config)

    def probe(url: str) -> Finding | None:
        authed = client.get(url)
        if not (authed.ok and authed.status == 200 and len(authed.text) > 200):
            return None
        if is_login_page(authed.text):
            return None
        unauth = bare.get(url)
        if unauth.ok and unauth.status == 200 and not is_login_page(unauth.text) and similar(authed.text, unauth.text):
            return Finding(
                title="Broken access control: protected resource reachable without authentication",
                severity=Severity.HIGH,
                target=host,
                category="broken-access-control",
                location=url,
                description="This resource returns the same content with and without a "
                "session, so it is not access-controlled.",
                remediation="Enforce server-side authorization on every request.",
                evidence=f"authenticated 200 == unauthenticated 200 ({len(unauth.text)} bytes)",
                source=_SOURCE,
                extra={"method": "unauthenticated-access"},
                proof=build_proof(unauth),
            )
        return None

    return [f for _u, f in parallel_map(probe, urls, workers=config.concurrency) if f]


def _cross_user_check(result, config, client, ui) -> list[Finding]:
    second = getattr(config, "second_cookie", "")
    if not second:
        return []
    host = result.target.host
    urls = [u for u in dict.fromkeys(result.urls) if in_scope(u, host) and _int_id_params(u)][:30]
    if not urls:
        return []
    other = HttpClient(timeout=min(config.timeout, 8.0), user_agent=config.user_agent,
                       rate_limit=config.rate_limit, headers={"Cookie": second})

    def probe(url: str) -> Finding | None:
        a = client.get(url)
        b = other.get(url)
        if a.ok and b.ok and a.status == 200 and b.status == 200 and not is_login_page(b.text):
            if a.text == b.text and len(a.text) > 100:
                return Finding(
                    title="IDOR confirmed: another user can access this object",
                    severity=Severity.HIGH,
                    target=host,
                    category="idor",
                    location=url,
                    description="A second user's session receives the first user's object "
                    "unchanged, confirming missing object-level authorization.",
                    remediation="Scope every object lookup to the authenticated user.",
                    evidence="both sessions returned identical content",
                    source=_SOURCE,
                    extra={"method": "cross-user"},
                    proof=build_proof(b),
                )
        return None

    return [f for _u, f in parallel_map(probe, urls, workers=config.concurrency) if f]


def _idor_tamper_check(result, config, client, ui) -> list[Finding]:
    host = result.target.host
    urls = [u for u in dict.fromkeys(result.urls) if in_scope(u, host) and _int_id_params(u)][:30]
    if not urls:
        return []

    def probe(url: str) -> Finding | None:
        params = _int_id_params(url)
        param, value = params[0]
        base = client.get(url)
        if not (base.ok and base.status == 200 and len(base.text) > 100):
            return None
        tampered_val = value - 1 if value > 1 else value + 1
        turl = _set_param(url, param, str(tampered_val))
        t = client.get(turl)
        if (t.ok and t.status == 200 and not is_login_page(t.text)
                and t.text != base.text and similar(base.text, t.text)):
            return Finding(
                title=f"Potential IDOR via parameter '{param}'",
                severity=Severity.MEDIUM,
                target=host,
                category="idor",
                location=turl,
                description=f"Changing '{param}' from {value} to {tampered_val} returned a "
                "different object of the same shape — likely missing object-level "
                "authorization. Verify the object belongs to another user.",
                remediation="Enforce per-user authorization on object references; use "
                "unguessable identifiers.",
                evidence=f"{param}={value} vs {param}={tampered_val} returned different content",
                source=_SOURCE,
                extra={"method": "id-tamper", "parameter": param},
                proof=build_proof(t),
            )
        return None

    return [f for _u, f in parallel_map(probe, urls, workers=config.concurrency) if f]


def check(result: ScanResult, config, client: HttpClient, ui) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_unauth_check(result, config, client, ui))
    findings.extend(_cross_user_check(result, config, client, ui))
    # Skip tamper candidates already covered by a confirmed cross-user IDOR location.
    covered = {f.location for f in findings if f.category == "idor"}
    for f in _idor_tamper_check(result, config, client, ui):
        if f.location not in covered:
            findings.append(f)
    return findings
