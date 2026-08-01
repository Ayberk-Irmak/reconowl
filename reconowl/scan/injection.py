"""Native injection probes: SQL-error-based SQLi and reflected-XSS candidates.

These are lightweight, safe, high-signal checks meant to *flag candidates*, not
to exploit. When ``run_sqlmap`` is set, confirmed-looking SQLi candidates are
handed to sqlmap for real confirmation.
"""

from __future__ import annotations

import html
import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof
from ..utils.tools import find_tool, run
from . import injpoints
from ._common import point_baselines

_SOURCE = "native:injection"

# Signatures of database errors triggered by a broken quote.
_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlstate[",
    "psql: error",
    "ora-01756",
    "ora-00933",
    "sqlite3::",
    "sqlite_error",
    "microsoft odbc",
    "odbc sql server driver",
    "mysql_fetch_array()",
    "supplied argument is not a valid mysql",
    "syntax error at or near",
    # SQLite / Python (apps with debug tracebacks leak these)
    "unrecognized token",
    "sqlite3.operationalerror",
    "sqlite3.programmingerror",
    "sqlalchemy.exc",
]

_SQLI_PAYLOAD = "'"
_XSS_MARKER = "reconowlXSS9271"
_XSS_PAYLOAD = f"<{_XSS_MARKER}>"


def _parametrized(urls: list[str], cap: int) -> list[str]:
    """Pick distinct URLs that carry query parameters, deduped by shape."""
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    out: list[str] = []
    for url in urls:
        parts = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qsl(parts.query)
        if not params:
            continue
        key = (parts.netloc, parts.path, tuple(sorted(k for k, _ in params)))
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
        if len(out) >= cap:
            break
    return out


def _mutate(url: str, param: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    mutated = [(k, (v + payload) if k == param else v) for k, v in params]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(mutated), "")
    )


def _sqlmap_confirm(url: str, config, timeout: float = 180.0) -> bool:
    """Best-effort confirmation with sqlmap --batch (returns True if injectable)."""
    if find_tool("sqlmap") is None:
        return False
    args = ["-u", url, "--batch", "--level", "1", "--risk", "1", "--smart", "--flush-session"]
    headers = dict(config.extra_headers) if config else {}
    cookie = config.cookie if config else ""
    if cookie:
        args += ["--cookie", cookie]
    for key, value in headers.items():
        args += ["-H", f"{key}: {value}"]
    code, out, _err = run("sqlmap", args, timeout=timeout)
    text = (out or "").lower()
    return "is vulnerable" in text or "sqlmap identified the following injection" in text


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    points = injpoints.build(result, result.target.host, cap=40)
    if not points:
        return []
    ui.info(f"Injection probes on {len(points)} injection point(s) (GET/POST/JSON)…")
    baselines = point_baselines(client, points, config.concurrency)

    def probe(point) -> list[Finding]:
        param = point.param
        base_text = baselines.get(injpoints.baseline_key(point), "").lower()
        base_val = point.params.get(param, "")

        # --- SQLi (error-based) ---
        resp = injpoints.send(client, point, base_val + _SQLI_PAYLOAD)
        if resp.ok:
            low = resp.text.lower()
            hit = next((sig for sig in _SQL_ERRORS if sig in low and sig not in base_text), None)
            if hit:
                confirmed = (
                    config.run_sqlmap and point.kind == "query"
                    and _sqlmap_confirm(injpoints._query_url(point, base_val + _SQLI_PAYLOAD, False), config)
                )
                return [Finding(
                    title=f"SQL injection candidate in parameter '{param}' ({point.kind})",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    target=result.target.host,
                    category="sqli",
                    location=point.location,
                    description=(
                        f"Injecting a single quote into '{param}' ({point.kind}) triggered "
                        "a database error, indicating the input reaches a SQL query "
                        "unsanitised." + (" Confirmed by sqlmap." if confirmed else "")
                    ),
                    remediation="Use parameterised queries / prepared statements.",
                    evidence=f"error signature: {hit}",
                    source="sqlmap" if confirmed else _SOURCE,
                    extra={"parameter": param, "transport": point.kind, "confirmed": confirmed},
                    proof=build_proof(resp),
                )]

        # --- Reflected XSS ---
        resp = injpoints.send(client, point, base_val + _XSS_PAYLOAD)
        if resp.ok and _XSS_PAYLOAD in resp.text and html.escape(_XSS_PAYLOAD) not in resp.text:
            return [Finding(
                title=f"Reflected XSS candidate in parameter '{param}' ({point.kind})",
                severity=Severity.MEDIUM,
                target=result.target.host,
                category="xss",
                location=point.location,
                description=(
                    f"The value of '{param}' ({point.kind}) is reflected into the "
                    "response without HTML-encoding, suggesting reflected XSS."
                ),
                remediation="Context-encode output and apply a strict CSP.",
                evidence=f"unencoded reflection of {_XSS_PAYLOAD}",
                source=_SOURCE,
                extra={"parameter": param, "transport": point.kind},
                proof=build_proof(resp),
            )]
        return []

    results: list[Finding] = []
    for _p, found in parallel_map(probe, points, workers=config.concurrency):
        if found:
            results.extend(found)
    return results
