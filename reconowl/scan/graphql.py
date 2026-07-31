"""Native check: GraphQL introspection and exposed GraphQL IDEs.

Probes common GraphQL endpoints with an introspection query. If the server
returns a schema, introspection is enabled — leaking the full API surface
(types, queries, mutations) that should be off in production. Also flags exposed
GraphiQL / GraphQL Playground IDEs and merely-present endpoints.
"""

from __future__ import annotations

import json
import urllib.parse

from ..models import Finding, Severity
from ..utils.net import HttpClient, build_proof, in_scope

_SOURCE = "native:graphql"

# Common locations for a GraphQL endpoint / IDE.
_GQL_PATHS = (
    "graphql", "api/graphql", "v1/graphql", "v2/graphql", "graphql/v1",
    "api/v1/graphql", "query", "gql", "api/gql", "graphql/console",
    "graphiql", "playground", "graphql-playground", "console", "subscriptions",
)

_IDE_PATHS = {"graphiql", "playground", "graphql-playground", "graphql/console", "console"}

# Minimal introspection query.
_INTROSPECTION = json.dumps(
    {"query": "query{__schema{queryType{name} mutationType{name} types{name}}}"}
)

_GQL_ERROR_MARKERS = (
    "must provide query string",
    "cannot query field",
    "syntax error",
    "must provide an operation",
    "query is required",
    "graphqlerror",
    "no query string was present",
)


def parse_introspection(text: str) -> bool:
    """True if the response body is a GraphQL introspection result with a schema."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    data = obj.get("data")
    return isinstance(data, dict) and bool(data.get("__schema"))


def schema_type_count(text: str) -> int:
    try:
        obj = json.loads(text)
        return len(obj["data"]["__schema"].get("types", []))
    except Exception:  # noqa: BLE001
        return 0


def looks_like_graphql(text: str) -> bool:
    """True if a response looks like a GraphQL endpoint (even introspection-off)."""
    low = text.lower()
    if '"errors"' not in low and '"data"' not in low:
        return False
    return any(m in low for m in _GQL_ERROR_MARKERS)


def is_graphiql(html: str) -> bool:
    """True if the page is a GraphiQL / GraphQL Playground IDE."""
    low = html.lower()
    return (
        "graphiql" in low
        or "graphql playground" in low
        or "graphql-playground" in low
        or "ide=graphql" in low
    )


def _candidates(result) -> list[str]:
    base = result.target.base_url
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if in_scope(url, result.target.host) and url not in seen:
            seen.add(url)
            urls.append(url)

    if base:
        for path in _GQL_PATHS:
            add(urllib.parse.urljoin(base + "/", path))
    # Endpoints/URLs already discovered that look GraphQL-ish.
    for u in [e.url for e in result.endpoints] + result.urls:
        low = urllib.parse.urlsplit(u).path.lower()
        if "graphql" in low or low.endswith("/gql") or "graphiql" in low:
            add(u)
    return urls


def _path_tail(url: str) -> str:
    return urllib.parse.urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1].lower()


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = _candidates(result)
    if not candidates:
        return []

    findings: list[Finding] = []
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    for url in candidates:
        resp = client.request("POST", url, headers=hdrs, data=_INTROSPECTION, allow_redirects=False)

        if resp.ok and resp.status == 200 and parse_introspection(resp.text):
            findings.append(
                Finding(
                    title="GraphQL introspection enabled",
                    severity=Severity.MEDIUM,
                    target=result.target.host,
                    category="graphql-introspection",
                    location=url,
                    description=(
                        "The GraphQL endpoint answers introspection queries, exposing "
                        "the full schema (types, queries, mutations) to any client."
                    ),
                    remediation="Disable introspection in production, or restrict it to "
                    "authenticated/internal clients.",
                    evidence=f"__schema returned {schema_type_count(resp.text)} types",
                    source=_SOURCE,
                    proof=build_proof(resp),
                )
            )
            continue

        # IDE exposure (check the paths that host an interactive console).
        if _path_tail(url) in _IDE_PATHS:
            ide = client.get(url)
            if ide.ok and is_graphiql(ide.text):
                findings.append(
                    Finding(
                        title="Exposed GraphQL IDE (GraphiQL/Playground)",
                        severity=Severity.MEDIUM,
                        target=result.target.host,
                        category="graphql-ide",
                        location=url,
                        description="An interactive GraphQL IDE is publicly reachable, "
                        "easing schema exploration and query crafting by attackers.",
                        remediation="Do not expose GraphiQL/Playground in production.",
                        source=_SOURCE,
                        proof=build_proof(ide),
                    )
                )
                continue

        if resp.ok and looks_like_graphql(resp.text):
            findings.append(
                Finding(
                    title="GraphQL endpoint found (introspection disabled)",
                    severity=Severity.INFO,
                    target=result.target.host,
                    category="graphql-endpoint",
                    location=url,
                    description="A GraphQL endpoint is present but did not answer the "
                    "introspection query.",
                    remediation="Confirm introspection and field suggestions are disabled.",
                    source=_SOURCE,
                    proof=build_proof(resp),
                )
            )
    return findings
