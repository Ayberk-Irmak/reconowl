"""Unit tests for request/response proof capture (with redaction)."""

from __future__ import annotations

from strix.utils.net import HttpResponse, build_proof


def test_build_proof_includes_request_and_response():
    resp = HttpResponse(
        url="http://a.com/item?id=1'", ok=True, status=200,
        headers={"Server": "nginx", "Content-Type": "text/html"},
        text="SQL syntax error near ...",
        request_method="GET", request_headers={"Accept": "text/html"},
    )
    proof = build_proof(resp)
    assert "GET http://a.com/item?id=1'" in proof["request"]
    assert "Accept: text/html" in proof["request"]
    assert "HTTP 200" in proof["response"]
    assert "Server: nginx" in proof["response"]
    assert "SQL syntax error" in proof["response"]


def test_build_proof_redacts_sensitive_headers():
    resp = HttpResponse(
        url="http://a.com/", ok=True, status=200,
        headers={"Set-Cookie": "session=topsecret"},
        text="ok",
        request_method="POST",
        request_headers={"Cookie": "session=topsecret", "Authorization": "Bearer x"},
        request_body="user=admin",
    )
    proof = build_proof(resp)
    assert "topsecret" not in proof["request"]
    assert "Cookie: [redacted]" in proof["request"]
    assert "Authorization: [redacted]" in proof["request"]
    assert "Set-Cookie: [redacted]" in proof["response"]
    assert "user=admin" in proof["request"]  # body kept


def test_build_proof_truncates_body():
    resp = HttpResponse(url="u", ok=True, status=200, headers={}, text="x" * 5000)
    proof = build_proof(resp, max_body=100)
    assert len(proof["response"]) < 300
