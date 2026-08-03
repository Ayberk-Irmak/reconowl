"""Injection points: a unified target for the injection-family checks.

A point is a single parameter that can be attacked over one transport:

- ``query`` — a GET query-string parameter.
- ``form``  — a POST ``application/x-www-form-urlencoded`` body field.
- ``json``  — a POST ``application/json`` body field.

``send()`` places a payload into the point's parameter and issues the request
with the right encoding for its transport, so a check written once tests GET,
POST-form, and JSON bodies alike.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field

from ..models import ScanResult
from ..utils.net import HttpClient, HttpResponse, in_scope

_FORM_CT = {"Content-Type": "application/x-www-form-urlencoded"}
_JSON_CT = {"Content-Type": "application/json"}


@dataclass
class InjectionPoint:
    method: str                       # GET | POST
    url: str                          # scheme://host/path (no query)
    param: str                        # the parameter under test
    kind: str                         # query | form | json
    params: dict[str, str] = field(default_factory=dict)  # baseline name->value

    @property
    def location(self) -> str:
        return f"{self.method} {self.url} ({self.kind}:{self.param})"

    def key(self) -> tuple[str, str, str, str]:
        return (self.method, self.url, self.kind, self.param)


def baseline_key(point: InjectionPoint) -> tuple[str, str, tuple]:
    """Key grouping points that share the same baseline request."""
    return (point.kind, point.url, tuple(sorted(point.params.items())))


def _query_url(point: InjectionPoint, value: str, raw: bool) -> str:
    if raw:
        others = "&".join(
            f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}"
            for k, v in point.params.items()
            if k != point.param
        )
        injected = f"{point.param}={value}"
        query = f"{others}&{injected}" if others else injected
    else:
        pairs = [(k, value if k == point.param else v) for k, v in point.params.items()]
        query = urllib.parse.urlencode(pairs)
    return point.url + ("?" + query if query else "")


def send(
    client: HttpClient,
    point: InjectionPoint,
    value: str,
    *,
    raw: bool = False,
    allow_redirects: bool = False,
) -> HttpResponse:
    """Issue a request with ``value`` placed in ``point.param``.

    ``raw`` (query only) injects a pre-encoded value without re-encoding it; it is
    ignored for form/json points, which always send the literal value.
    """
    if point.kind == "query":
        return client.get(_query_url(point, value, raw), allow_redirects=allow_redirects)
    body = dict(point.params)
    body[point.param] = value
    if point.kind == "json":
        return client.request("POST", point.url, headers=_JSON_CT,
                              data=json.dumps(body), allow_redirects=allow_redirects)
    return client.request("POST", point.url, headers=_FORM_CT,
                          data=urllib.parse.urlencode(body), allow_redirects=allow_redirects)


def send_json_value(client: HttpClient, point: InjectionPoint, raw_value, *, allow_redirects=False) -> HttpResponse:
    """POST a JSON body where ``point.param`` is set to a raw (non-string) value.

    Used for NoSQL operator injection, e.g. ``{"user": {"$ne": null}}``.
    """
    body = dict(point.params)
    body[point.param] = raw_value
    return client.request("POST", point.url, headers=_JSON_CT,
                          data=json.dumps(body), allow_redirects=allow_redirects)


def baseline(client: HttpClient, point: InjectionPoint) -> HttpResponse:
    """Fetch the point's response with original parameter values."""
    return send(client, point, point.params.get(point.param, ""))


# --------------------------------------------------------------------------- #
# Building points from recon assets
# --------------------------------------------------------------------------- #
def _ordered_urls(result: ScanResult) -> list[str]:
    """URLs with actively-discovered (crawled/live) ones first, archive URLs last.

    Passive recon can harvest hundreds of archived URLs that get placed ahead of
    the freshly-crawled, confirmed-live URLs; without this ordering the per-check
    injection-point cap would test stale archive URLs and miss real endpoints.
    """
    live = set(getattr(result, "crawled", set())) | {e.url for e in result.endpoints}
    first = [u for u in result.urls if u in live]
    rest = [u for u in result.urls if u not in live]
    return first + rest


def _url_query_points(result: ScanResult, host: str, param_filter) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    for url in _ordered_urls(result):
        if not in_scope(url, host):
            continue
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if not pairs:
            continue
        params = dict(pairs)
        base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        for name in params:
            if param_filter and name.lower() not in param_filter:
                continue
            points.append(InjectionPoint("GET", base, name, "query", dict(params)))
    return points


def _form_points(result: ScanResult, host: str, param_filter) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    for form in result.forms:
        if form.method.upper() != "POST" or not in_scope(form.url, host):
            continue
        base_params = {n: "1" for n in form.params}
        kinds = ["form"]
        low = form.url.lower()
        if "api" in low or "json" in low or "graphql" in low:
            kinds.append("json")
        for name in form.params:
            if param_filter and name.lower() not in param_filter:
                continue
            for kind in kinds:
                points.append(InjectionPoint("POST", form.url, name, kind, dict(base_params)))
    return points


def base_points(base_url: str, param_names, param_filter=None) -> list[InjectionPoint]:
    """GET query points on the base URL for a set of guessed parameter names."""
    if not base_url:
        return []
    parts = urllib.parse.urlsplit(base_url.rstrip("/") + "/")
    base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    points = []
    for name in param_names:
        if param_filter and name.lower() not in param_filter:
            continue
        points.append(InjectionPoint("GET", base, name, "query", {name: "1"}))
    return points


def build(
    result: ScanResult,
    host: str,
    *,
    base_param_names=(),
    param_filter=None,
    cap: int = 40,
) -> list[InjectionPoint]:
    """Assemble deduplicated injection points from URLs, forms, and base probes."""
    points = (
        _url_query_points(result, host, param_filter)
        + _form_points(result, host, param_filter)
        + base_points(result.target.base_url, base_param_names, param_filter)
    )
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[InjectionPoint] = []
    for p in points:
        if p.key() not in seen:
            seen.add(p.key())
            unique.append(p)
    return unique[:cap]
