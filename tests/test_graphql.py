"""Unit tests for the GraphQL introspection check."""

from __future__ import annotations

from strix.models import ScanResult, Target
from strix.scan import graphql
from strix.utils.net import HttpResponse

_SCHEMA = '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"},{"name":"Post"}]}}}'


def test_parse_introspection_positive_and_negative():
    assert graphql.parse_introspection(_SCHEMA) is True
    assert graphql.parse_introspection('{"data":{"user":null}}') is False
    assert graphql.parse_introspection('{"errors":[{"message":"x"}]}') is False
    assert graphql.parse_introspection("not json") is False


def test_schema_type_count():
    assert graphql.schema_type_count(_SCHEMA) == 2
    assert graphql.schema_type_count("{}") == 0


def test_looks_like_graphql():
    assert graphql.looks_like_graphql('{"errors":[{"message":"Must provide query string"}]}')
    assert graphql.looks_like_graphql('{"errors":[{"message":"Cannot query field x"}]}')
    assert not graphql.looks_like_graphql("<html>404 not found</html>")
    assert not graphql.looks_like_graphql('{"data":{"ok":true}}')  # no gql error marker


def test_is_graphiql():
    assert graphql.is_graphiql("<html><div id='graphiql'>Loading GraphiQL</div></html>")
    assert graphql.is_graphiql("<title>GraphQL Playground</title>")
    assert not graphql.is_graphiql("<html>normal page</html>")


def test_candidates_include_common_paths_in_scope():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    urls = graphql._candidates(r)
    assert "https://a.com/graphql" in urls
    assert any(u.endswith("/graphiql") for u in urls)


def test_check_detects_introspection_and_ide():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))

    class Client:
        def request(self, method, url, headers=None, data=None, allow_redirects=True):
            if url == "https://a.com/graphql":
                return HttpResponse(url=url, ok=True, status=200, headers={}, text=_SCHEMA)
            return HttpResponse(url=url, ok=True, status=404, headers={}, text="not found")

        def get(self, url, **kwargs):
            if url.endswith("/graphiql"):
                return HttpResponse(url=url, ok=True, status=200, headers={},
                                    text="<div id='graphiql'>GraphiQL</div>")
            return HttpResponse(url=url, ok=True, status=404, headers={}, text="nope")

    class UI:
        def info(self, m): pass

    from strix.config import ScanConfig
    findings = graphql.check(r, ScanConfig(), Client(), UI())
    cats = {f.category for f in findings}
    assert "graphql-introspection" in cats
    assert "graphql-ide" in cats
    intro = next(f for f in findings if f.category == "graphql-introspection")
    assert "2 types" in intro.evidence
