"""Unit tests for OpenAPI/Swagger discovery and parsing."""

from __future__ import annotations

from reconowl.config import ScanConfig
from reconowl.models import ScanResult, Target
from reconowl.scan import openapi
from reconowl.utils.net import HttpResponse

OAS3 = {
    "openapi": "3.0.1",
    "info": {"title": "Shop API"},
    "servers": [{"url": "https://a.com/api/v2"}],
    "paths": {
        "/users/{id}": {
            "get": {"parameters": [
                {"in": "path", "name": "id"},
                {"in": "query", "name": "expand"},
            ]},
        },
        "/login": {
            "post": {"requestBody": {"content": {"application/json": {"schema": {
                "properties": {"username": {}, "password": {}}}}}}},
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy"},
    "basePath": "/v1",
    "paths": {
        "/search": {"get": {"parameters": [{"in": "query", "name": "q"}]}},
        "/items": {"post": {"parameters": [
            {"in": "body", "name": "b", "schema": {"properties": {"title": {}, "qty": {}}}}]}},
    },
}


def test_is_spec():
    assert openapi.is_spec(OAS3) is True
    assert openapi.is_spec({"paths": {}}) is False
    assert openapi.is_spec({"openapi": "3.0"}) is False  # no paths


def test_discover_paths_and_known_urls():
    urls = openapi.discover_spec_urls("https://a.com", ["https://a.com/x/openapi.json"], "a.com")
    assert "https://a.com/openapi.json" in urls
    assert "https://a.com/v3/api-docs" in urls
    assert "https://a.com/x/openapi.json" in urls  # spec-looking known URL


def test_parse_oas3_paths_query_body_and_prefix():
    ops = openapi.parse_spec(OAS3, "https://a.com")
    by = {(o["method"], o["url"]): o for o in ops}
    get = by[("GET", "https://a.com/api/v2/users/1")]  # server prefix + path param -> 1
    assert get["query"] == ["expand"]
    post = by[("POST", "https://a.com/api/v2/login")]
    assert set(post["body"]) == {"username", "password"}


def test_parse_swagger2_basepath_and_body_schema():
    ops = openapi.parse_spec(SWAGGER2, "https://a.com")
    urls = {o["url"]: o for o in ops}
    assert urls["https://a.com/v1/search"]["query"] == ["q"]
    assert set(urls["https://a.com/v1/items"]["body"]) == {"title", "qty"}


def test_feed_adds_urls_and_forms():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    ops = openapi.parse_spec(OAS3, "https://a.com")
    added_urls, added_forms = openapi._feed(r, "a.com", ops)
    assert added_urls == 1 and added_forms == 1
    assert "https://a.com/api/v2/users/1?expand=1" in r.urls
    assert any(f.url == "https://a.com/api/v2/login" and set(f.params) == {"username", "password"}
               for f in r.forms)


def _client(spec_url, doc_text):
    class Client:
        def get(self, url, **k):
            if url == spec_url:
                return HttpResponse(url=url, ok=True, status=200, headers={}, text=doc_text)
            return HttpResponse(url=url, ok=True, status=404, headers={}, text="")
    return Client()


def test_check_end_to_end_produces_finding_and_feeds():
    import json
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    spec_url = "https://a.com/openapi.json"

    class UI:
        def good(self, m): pass
        def warn(self, m): pass

    findings = openapi.check(r, ScanConfig(target="a.com"),
                             _client(spec_url, json.dumps(OAS3)), UI())
    assert len(findings) == 1
    assert findings[0].category == "openapi-exposed"
    assert r.urls and r.forms  # operations were fed to the injection surface


def test_disabled_via_config():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    assert openapi.check(r, ScanConfig(target="a.com", openapi=False), None, None) == []
