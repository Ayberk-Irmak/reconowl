"""Native check: NoSQL (MongoDB-style) injection.

Two high-signal, low-false-positive strategies:

- **Error-based** — inject payloads that break a NoSQL query and look for
  MongoDB/Mongoose error signatures in the response.
- **Operator differential** — send ``param[$ne]=<rand>`` versus
  ``param[$eq]=<rand>``. A backend that parses bracket operators (the vulnerable
  case) answers the two very differently ($ne matches everything, $eq matches
  nothing); one that treats them as literal strings answers identically, so a
  clear difference is the signal.
"""

from __future__ import annotations

import secrets
import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, HttpResponse, build_proof, in_scope
from . import injpoints
from ._common import point_baselines
from .redirect import _set_param

_SOURCE = "native:nosqli"

_BASE_PARAMS = ("id", "user", "username", "name", "q", "search", "email", "filter")

_NOSQL_ERRORS = (
    "mongoerror", "mongoservererror", "mongoparseerror", "mongonetworkerror",
    "bsonerror", "bson field", "e11000", "$where", "unknown operator",
    "failed to parse", "casterror", "com.mongodb", "mongoclient",
    "unterminated string", "couchdb", "unexpected token o in json",
)

_ERROR_PAYLOADS = (
    "'", '"', "\\", "';return(true);//", '{"$gt":""}', "'||'1'=='1", "\";return true;//",
)

_LEN_DIFF_RATIO = 0.30  # >30% body-length change counts as "significantly different"


def detect_error(text: str, baseline: str = "") -> str | None:
    """Return the NoSQL error signature found in ``text`` (new vs baseline)."""
    low = (text or "").lower()
    base = (baseline or "").lower()
    for sig in _NOSQL_ERRORS:
        if sig in low and sig not in base:
            return sig
    return None


def significant_diff(a: HttpResponse, b: HttpResponse) -> bool:
    """True if two responses differ enough to imply different result sets."""
    if not (a.ok and b.ok):
        return False
    if a.status != b.status:
        return True
    la, lb = len(a.text), len(b.text)
    longest = max(la, lb) or 1
    return abs(la - lb) / longest > _LEN_DIFF_RATIO


def _set_bracket(url: str, param: str, op: str, value: str) -> str:
    """Rewrite ``param=..`` to ``param[$op]=value`` (operator injection)."""
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if k != param]
    kept.append((f"{param}[${op}]", value))
    query = urllib.parse.urlencode(kept)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _candidates(result, cap: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(url: str, param: str) -> None:
        parts = urllib.parse.urlsplit(url)
        key = (parts.netloc, parts.path, param)
        if key not in seen:
            seen.add(key)
            out.append((url, param))

    for url in result.urls:
        if not in_scope(url, result.target.host):
            continue
        for key, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True):
            add(url, key)

    base = result.target.base_url
    if base:
        for param in ("id", "user", "username", "name", "q", "search", "email", "filter"):
            add(base.rstrip("/") + "/", param)

    return out[:cap]


def _finding(result, url: str, param: str, method: str, evidence: str, resp=None) -> Finding:
    return Finding(
        title=f"NoSQL injection in parameter '{param}' ({method})",
        severity=Severity.HIGH,
        target=result.target.host,
        category="nosql-injection",
        location=url,
        description=(
            f"The '{param}' parameter is vulnerable to NoSQL injection ({method}). "
            "This can bypass authentication or extract data from the database."
        ),
        remediation="Validate/cast input types, reject object/operator values for "
        "string fields, and use a query builder that separates operators from data.",
        evidence=evidence,
        proof=build_proof(resp) if resp is not None else {},
        source=_SOURCE,
        extra={"parameter": param, "method": method},
    )


def _operator(client, point, op: str, value):
    """Send an operator-injection request ($ne/$eq) for a point's transport."""
    if point.kind == "json":
        return injpoints.send_json_value(client, point, {f"${op}": value})
    # query/form: bracket notation, e.g. param[$ne]=value
    bracket = f"{point.param}[${op}]"
    params = {k: v for k, v in point.params.items() if k != point.param}
    params[bracket] = value
    if point.kind == "query":
        query = urllib.parse.urlencode(params)
        return client.get(point.url + ("?" + query if query else ""), allow_redirects=False)
    return client.request(
        "POST", point.url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urllib.parse.urlencode(params), allow_redirects=False,
    )


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = injpoints.build(
        result, result.target.host, base_param_names=_BASE_PARAMS, cap=20
    )
    if not candidates:
        return []

    baseline_cache = point_baselines(client, candidates, config.concurrency)
    findings: list[Finding] = []
    flagged: set = set()

    # --- Error-based (all transports) ---
    def err_probe(point) -> Finding | None:
        for payload in _ERROR_PAYLOADS:
            resp = injpoints.send(client, point, payload)
            if not resp.ok:
                continue
            sig = detect_error(resp.text, baseline_cache.get(injpoints.baseline_key(point), ""))
            if sig:
                return _finding(result, point.location, point.param,
                                f"error-based/{point.kind}", f"NoSQL error signature: {sig}", resp)
        return None

    for point, finding in parallel_map(err_probe, candidates, workers=config.concurrency):
        if finding is not None:
            flagged.add(point.key())
            findings.append(finding)

    # --- Operator differential ($ne vs $eq), all transports ---
    def op_probe(point) -> Finding | None:
        rand = "reconowlnos" + secrets.token_hex(4)
        neq = _operator(client, point, "ne", rand)
        eq = _operator(client, point, "eq", rand)
        if significant_diff(neq, eq):
            return _finding(
                result, point.location, point.param, f"operator/{point.kind}",
                f"[$ne] vs [$eq] responses differ (status {neq.status}/{eq.status}, "
                f"len {len(neq.text)}/{len(eq.text)})", neq,
            )
        return None

    remaining = [p for p in candidates if p.key() not in flagged]
    for _p, finding in parallel_map(op_probe, remaining, workers=config.concurrency):
        if finding is not None:
            findings.append(finding)

    return findings
