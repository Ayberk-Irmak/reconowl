"""Unit tests for the JWT weaknesses check."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from reconowl.models import ScanResult, Severity, Target
from reconowl.scan import jwt as jwtcheck
from reconowl.utils.net import HttpResponse


def _b64(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _make_jwt(header: dict, payload: dict, secret: str | None) -> str:
    h, p = _b64(header), _b64(payload)
    signing_input = f"{h}.{p}".encode()
    if secret is None:
        return f"{h}.{p}."
    alg = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[header["alg"]]
    sig = hmac.new(secret.encode(), signing_input, alg).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def test_find_and_decode():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"user": "a", "exp": 1}, "secret")
    found = jwtcheck.find_jwts(f"session={tok}; Path=/")
    assert found == [tok]
    assert jwtcheck.decode_part(tok.split(".")[0])["alg"] == "HS256"
    # A random base64-ish blob is not mistaken for a JWT.
    assert jwtcheck.find_jwts("abc.def.ghi") == []


def test_crack_hmac_finds_weak_secret():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"u": 1}, "secret")
    assert jwtcheck.crack_hmac(tok, jwtcheck._SECRETS) == "secret"
    strong = _make_jwt({"alg": "HS256"}, {"u": 1}, "an-extremely-long-unguessable-random-key-xyz")
    assert jwtcheck.crack_hmac(strong, jwtcheck._SECRETS) is None


def test_analyze_alg_none():
    tok = _make_jwt({"alg": "none", "typ": "JWT"}, {"user": "admin", "exp": 1}, None)
    kinds = {i["kind"] for i in jwtcheck.analyze(tok)}
    assert "alg-none" in kinds


def test_analyze_weak_secret_and_no_exp_and_sensitive():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"user": "admin", "password": "x"}, "secret")
    issues = {i["kind"]: i for i in jwtcheck.analyze(tok)}
    assert issues["weak-secret"]["severity"] is Severity.CRITICAL
    assert "no-exp" in issues
    assert "sensitive-claims" in issues


def test_analyze_clean_token_minimal_issues():
    tok = _make_jwt({"alg": "HS256"}, {"sub": "123", "exp": 9999999999},
                    "an-extremely-long-unguessable-random-key-xyz")
    kinds = {i["kind"] for i in jwtcheck.analyze(tok)}
    assert "weak-secret" not in kinds and "alg-none" not in kinds and "no-exp" not in kinds


def test_check_reads_jwt_from_cookie():
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"role": "admin"}, "secret")
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))

    class Client:
        def get(self, url, **kwargs):
            return HttpResponse(url=url, ok=True, status=200,
                                headers={"Set-Cookie": f"session={tok}; HttpOnly"}, text="hi")

    class UI:
        def info(self, m): pass

    findings = jwtcheck.check(r, None, Client(), UI())
    cats = {f.category for f in findings}
    assert "jwt-weak-secret" in cats  # CRITICAL forgeable
    assert any(f.severity is Severity.CRITICAL for f in findings)
