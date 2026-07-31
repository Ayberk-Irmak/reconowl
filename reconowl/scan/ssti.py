"""Native check: Server-Side Template Injection (SSTI).

Injects arithmetic template expressions for several engines and looks for the
*evaluated* product in the response (not the literal payload). A distinctive
product that appears only after injection — and wasn't in the baseline — means
the server evaluated the expression, i.e. the input reaches a template engine.
"""

from __future__ import annotations

import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope
from . import injpoints
from ._common import point_baselines

_SOURCE = "native:ssti"

# Two primes whose product is a distinctive 7-digit number unlikely to occur by
# chance in a page.
_A, _B = 1009, 1013
_PRODUCT = str(_A * _B)  # "1022117"
_EXPR = f"{_A}*{_B}"

# One payload per common template syntax. ``engine`` is for the evidence string.
_PAYLOADS = (
    ("{{" + _EXPR + "}}", "Jinja2/Twig/Angular"),
    ("${" + _EXPR + "}", "FreeMarker/JSP-EL/Spring"),
    ("#{" + _EXPR + "}", "Ruby/JSF"),
    ("<%= " + _EXPR + " %>", "ERB/EJS"),
    ("${{" + _EXPR + "}}", "generic ${{ }}"),
    ("@(" + _EXPR + ")", "Razor"),
    ("{" + _EXPR + "}", "Tornado/other"),
)

# Parameter names that commonly reflect input into a rendered page.
_REFLECT_PARAMS = (
    "q", "s", "search", "query", "name", "page", "lang", "keyword", "input",
    "message", "msg", "title", "id", "view", "content", "text", "data",
)


def detect(text: str, payload: str, product: str = _PRODUCT, baseline: str = "") -> bool:
    """True if ``product`` appears as an evaluated value (not literal reflection)."""
    if product in baseline:
        return False
    return product in text and payload not in text


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
        parts = urllib.parse.urlsplit(url)
        for key, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            add(url, key)

    base = result.target.base_url
    if base:
        for param in _REFLECT_PARAMS:
            add(base.rstrip("/") + "/", param)

    return out[:cap]


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    points = injpoints.build(result, result.target.host, base_param_names=_REFLECT_PARAMS, cap=25)
    if not points:
        return []

    baseline_cache = point_baselines(client, points, config.concurrency)

    def probe(point) -> list[Finding]:
        param = point.param
        baseline = baseline_cache.get(injpoints.baseline_key(point), "")
        if _PRODUCT in baseline:
            return []
        for payload, engine in _PAYLOADS:
            resp = injpoints.send(client, point, payload)
            if resp.ok and detect(resp.text, payload, baseline=baseline):
                return [Finding(
                    title=f"Server-Side Template Injection in parameter '{param}' ({point.kind})",
                    severity=Severity.HIGH,
                    target=result.target.host,
                    category="ssti",
                    location=point.location,
                    description=(
                        f"The '{param}' parameter ({point.kind}) is evaluated by a "
                        f"server-side template engine ({engine}): the expression {_EXPR} "
                        f"rendered as {_PRODUCT}. SSTI commonly escalates to "
                        "remote code execution."
                    ),
                    remediation="Never render user input as a template; use a sandbox "
                    "and pass user data only as bound variables.",
                    evidence=f"payload={payload} rendered {_EXPR}={_PRODUCT}",
                    source=_SOURCE,
                    extra={"parameter": param, "engine": engine, "transport": point.kind},
                    proof=build_proof(resp),
                )]
        return []

    findings: list[Finding] = []
    for _p, found in parallel_map(probe, points, workers=config.concurrency):
        if found:
            findings.extend(found)
    return findings
