"""Native check: OpenAPI / Swagger specification discovery and parsing.

Finds a published API spec (Swagger 2.0 or OpenAPI 3.x, JSON or — if PyYAML is
present — YAML), then enumerates every operation's path/query/body parameters
and feeds them to the injection-family checks:

- **GET** operations become parametrized URLs in ``result.urls`` (query-string
  injection points), and
- **POST** operations become synthetic forms in ``result.forms`` (form/JSON body
  injection points).

A publicly reachable spec is also reported as an information-disclosure finding
(it lists every endpoint and parameter — useful to an attacker if unintended).
Everything stays on the target's own origin so payloads never leave scope.
"""

from __future__ import annotations

import json
import urllib.parse

from ..models import Finding, Form, ScanResult, Severity
from ..utils.net import in_scope

_SOURCE = "native:openapi"

# Common locations where frameworks publish the spec.
_SPEC_PATHS = (
    "openapi.json", "swagger.json", "v2/api-docs", "v3/api-docs", "api-docs",
    "swagger/v1/swagger.json", "api/swagger.json", "api/openapi.json",
    "api/v1/openapi.json", "openapi.yaml", "swagger.yaml", "docs/swagger.json",
    "v1/api-docs", ".well-known/openapi.json", "swagger/docs/v1",
)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def discover_spec_urls(base_url: str, known_urls: list[str], host: str) -> list[str]:
    """Candidate spec URLs: common paths on the base + spec-looking known URLs."""
    out: list[str] = []
    seen: set[str] = set()

    def add(u: str) -> None:
        if u not in seen and in_scope(u, host):
            seen.add(u)
            out.append(u)

    if base_url:
        root = base_url.rstrip("/") + "/"
        for p in _SPEC_PATHS:
            add(urllib.parse.urljoin(root, p))
    for u in known_urls:
        low = u.lower()
        if any(m in low for m in ("swagger.json", "openapi.json", "api-docs", "openapi.yaml", "swagger.yaml")):
            add(u)
    return out


def _load(text: str, url: str) -> dict | None:
    text = (text or "").lstrip()
    if text.startswith("{"):
        try:
            doc = json.loads(text)
            return doc if isinstance(doc, dict) else None
        except ValueError:
            return None
    if url.lower().endswith((".yaml", ".yml")) or text.startswith(("swagger:", "openapi:")):
        try:
            import yaml  # optional
            doc = yaml.safe_load(text)
            return doc if isinstance(doc, dict) else None
        except Exception:  # noqa: BLE001 - no PyYAML or bad YAML
            return None
    return None


def is_spec(doc: dict) -> bool:
    return isinstance(doc, dict) and ("swagger" in doc or "openapi" in doc) and isinstance(doc.get("paths"), dict)


def _resolve_ref(doc: dict, ref: str) -> dict:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node: object = doc
    for part in ref[2:].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _schema_fields(doc: dict, schema: dict, depth: int = 0) -> list[str]:
    """Top-level property names of a (possibly $ref'd / allOf) request-body schema."""
    if not isinstance(schema, dict) or depth > 4:
        return []
    if "$ref" in schema:
        return _schema_fields(doc, _resolve_ref(doc, schema["$ref"]), depth + 1)
    fields: list[str] = []
    props = schema.get("properties")
    if isinstance(props, dict):
        fields.extend(props.keys())
    for sub in schema.get("allOf", []) or []:
        fields.extend(_schema_fields(doc, sub, depth + 1))
    return list(dict.fromkeys(fields))


def _spec_prefix(doc: dict) -> str:
    """The path prefix (basePath / servers[0] path) that precedes each operation path."""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        return urllib.parse.urlsplit(url).path.rstrip("/") if url else ""
    base_path = doc.get("basePath", "")
    return base_path.rstrip("/") if isinstance(base_path, str) else ""


def parse_spec(doc: dict, origin: str) -> list[dict]:
    """Return operations as ``{method, url, query, body}`` on the target origin."""
    prefix = _spec_prefix(doc)
    ops: list[dict] = []
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        return ops
    for raw_path, item in paths.items():
        if not isinstance(item, dict) or not isinstance(raw_path, str):
            continue
        shared = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = shared + (op.get("parameters", []) if isinstance(op.get("parameters"), list) else [])
            query, body, path_names = [], [], []
            for p in params:
                if not isinstance(p, dict):
                    continue
                loc, name = p.get("in"), p.get("name")
                if not name:
                    continue
                if loc == "query":
                    query.append(name)
                elif loc == "path":
                    path_names.append(name)
                elif loc in ("body", "formData"):
                    if loc == "body":
                        body.extend(_schema_fields(doc, p.get("schema", {})))
                    else:
                        body.append(name)
            # OpenAPI 3 requestBody
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                content = rb.get("content", {})
                if isinstance(content, dict):
                    for ct, media in content.items():
                        if isinstance(media, dict):
                            body.extend(_schema_fields(doc, media.get("schema", {})))
            # Build a concrete, in-scope URL (path params -> "1").
            concrete = prefix + raw_path
            concrete = urllib.parse.urljoin(origin.rstrip("/") + "/", concrete.lstrip("/"))
            for name in path_names:
                concrete = concrete.replace("{" + name + "}", "1")
            concrete = urllib.parse.urlsplit(concrete)
            concrete = urllib.parse.urlunsplit((concrete.scheme, concrete.netloc, concrete.path, "", ""))
            ops.append({
                "method": method.upper(),
                "url": concrete,
                "query": list(dict.fromkeys(query)),
                "body": list(dict.fromkeys(body)),
            })
    return ops


def _feed(result: ScanResult, host: str, ops: list[dict], cap: int = 80) -> tuple[int, int]:
    """Add GET operations as URLs and POST operations as forms; return (urls, forms)."""
    known = set(result.urls)
    form_keys = {(f.url, f.method, tuple(f.params)) for f in result.forms}
    added_urls = added_forms = 0
    for op in ops[:cap]:
        url = op["url"]
        if not in_scope(url, host):
            continue
        if op["method"] == "GET":
            if op["query"]:
                query = urllib.parse.urlencode([(n, "1") for n in op["query"]])
                full = url + "?" + query
            else:
                full = url
            if full not in known:
                known.add(full)
                result.urls.append(full)
                added_urls += 1
        elif op["method"] in ("POST", "PUT", "PATCH"):
            fields = list(dict.fromkeys(op["body"] + op["query"]))
            if not fields:
                continue
            key = (url, "POST", tuple(fields))
            if key not in form_keys:
                form_keys.add(key)
                result.forms.append(Form(url=url, method="POST", params=fields))
                added_forms += 1
    return added_urls, added_forms


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    if not getattr(config, "openapi", True):
        return []
    base = result.target.base_url
    host = result.target.host
    origin_parts = urllib.parse.urlsplit(base) if base else None
    origin = f"{origin_parts.scheme}://{origin_parts.netloc}" if origin_parts else ""

    for spec_url in discover_spec_urls(base, result.urls, host):
        resp = client.get(spec_url)
        if not resp.ok or resp.status != 200:
            continue
        doc = _load(resp.text, spec_url)
        if not doc or not is_spec(doc):
            continue

        ops = parse_spec(doc, origin)
        added_urls, added_forms = _feed(result, host, ops)
        version = doc.get("openapi") or doc.get("swagger") or "?"
        title = (doc.get("info", {}) or {}).get("title", "API") if isinstance(doc.get("info"), dict) else "API"
        ui.good(f"OpenAPI: parsed {len(ops)} operation(s) from {spec_url} "
                f"(+{added_urls} URL, +{added_forms} form)")
        return [Finding(
            title=f"Exposed API specification ({title}, {len(ops)} operations)",
            severity=Severity.LOW,
            target=host,
            category="openapi-exposed",
            location=spec_url,
            description=f"A machine-readable API spec (OpenAPI/Swagger {version}) is publicly "
            f"reachable at {spec_url}, enumerating {len(ops)} operations with their parameters. "
            "If the API is not meant to be public this discloses the full attack surface; the "
            "operations were fed into Strix's injection checks.",
            remediation="Restrict access to the API spec (auth / internal network) if it is not "
            "intended to be public, and ensure every operation enforces authN/Z.",
            evidence=f"{len(ops)} operations; e.g. " +
            ", ".join(f"{o['method']} {urllib.parse.urlsplit(o['url']).path}" for o in ops[:5]),
            source=_SOURCE,
            extra={"operations": len(ops), "version": str(version)},
        )]
    return []
