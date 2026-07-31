"""Native check: JSON Web Token (JWT) weaknesses.

Harvests JWTs from response cookies/headers/bodies and analyses them offline:

- ``alg: none`` — the app issued an unsigned token (forgeable).
- **Weak HMAC secret** — the HS256/384/512 signature is brute-forced against a
  built-in list of common secrets; a hit means tokens can be forged.
- **No expiry** — the token has no ``exp`` claim.
- **Sensitive claims** — password/secret-like data sitting in the (only base64,
  not encrypted) payload.

All analysis is offline crypto/decoding, so findings are deterministic and
low-false-positive.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from ..models import Finding, Severity
from ..utils.net import HttpClient

_SOURCE = "native:jwt"

# Three base64url segments; the header segment of a JWT starts with "eyJ".
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Common/default JWT signing secrets to brute-force against.
_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt", "jwtsecret", "jwt_secret",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "mysecret",
    "password", "passw0rd", "123456", "changeme", "admin", "test", "key",
    "private", "privatekey", "token", "s3cr3t", "qwerty", "letmein",
    "jsonwebtoken", "default", "app_secret", "signingkey", "hmac", "shhhh",
    "0000", "1234567890", "secretsecret", "topsecret", "mypassword",
]

_SENSITIVE_KEYS = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "access_key",
    "private_key", "ssn", "credit_card", "card", "cvv", "pin", "token",
)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_part(segment: str) -> dict:
    """Decode a base64url JWT segment into a dict (empty on failure)."""
    try:
        return json.loads(_b64url_decode(segment).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return {}


def find_jwts(text: str) -> list[str]:
    """Extract things that decode as real JWTs (header is JSON with an alg)."""
    out: list[str] = []
    seen: set[str] = set()
    for match in _JWT_RE.findall(text or ""):
        if match in seen:
            continue
        header = decode_part(match.split(".")[0])
        if "alg" in header or "typ" in header:
            seen.add(match)
            out.append(match)
    return out


def crack_hmac(token: str, secrets: list[str]) -> str | None:
    """Return the secret that validates the token's HMAC signature, or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = decode_part(parts[0])
    hasher = _HMAC_ALGS.get(str(header.get("alg", "")).upper())
    if hasher is None:
        return None
    try:
        signature = _b64url_decode(parts[2])
    except Exception:  # noqa: BLE001
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in secrets:
        expected = hmac.new(secret.encode(), signing_input, hasher).digest()
        if hmac.compare_digest(expected, signature):
            return secret
    return None


def analyze(token: str, secrets: list[str] | None = None) -> list[dict]:
    """Return a list of issue dicts for one JWT (pure / offline)."""
    secrets = secrets if secrets is not None else _SECRETS
    header = decode_part(token.split(".")[0])
    payload = decode_part(token.split(".")[1]) if token.count(".") >= 2 else {}
    alg = str(header.get("alg", "")).lower()
    issues: list[dict] = []

    if alg in ("none", ""):
        issues.append({
            "kind": "alg-none", "severity": Severity.HIGH,
            "title": "JWT uses 'alg: none' (unsigned token)",
            "description": "The token is unsigned, so anyone can forge one with "
            "arbitrary claims.",
            "remediation": "Reject 'none' and enforce a fixed, strong signing algorithm.",
            "evidence": f"header.alg={header.get('alg')!r}",
        })

    cracked = crack_hmac(token, secrets) if alg in ("hs256", "hs384", "hs512") else None
    if cracked is not None:
        issues.append({
            "kind": "weak-secret", "severity": Severity.CRITICAL,
            "title": f"JWT signed with a weak secret ('{cracked}')",
            "description": "The HMAC signing secret was brute-forced, so valid tokens "
            "with any claims (e.g. admin) can be forged.",
            "remediation": "Use a long, random secret (>=256 bits) stored securely.",
            "evidence": f"alg={alg.upper()} secret={cracked!r}",
        })

    if payload and "exp" not in payload:
        issues.append({
            "kind": "no-exp", "severity": Severity.LOW,
            "title": "JWT has no expiration (exp) claim",
            "description": "Tokens without an expiry stay valid indefinitely if leaked.",
            "remediation": "Set a short 'exp' and rotate/refresh tokens.",
            "evidence": f"claims={sorted(payload)}",
        })

    exposed = [k for k in payload if any(s in k.lower() for s in _SENSITIVE_KEYS)]
    if exposed:
        issues.append({
            "kind": "sensitive-claims", "severity": Severity.LOW,
            "title": "JWT payload exposes sensitive claim(s)",
            "description": "JWT payloads are base64-encoded, not encrypted; sensitive "
            "values are readable by anyone holding the token.",
            "remediation": "Keep secrets out of the token; store only opaque identifiers.",
            "evidence": f"claim(s): {', '.join(exposed)}",
        })

    return issues


def _collect_tokens(result, client: HttpClient) -> dict[str, str]:
    """Map each discovered JWT to the URL it was seen on."""
    targets = [e.url for e in result.endpoints] or (
        [result.target.base_url] if result.target.base_url else []
    )
    tokens: dict[str, str] = {}
    for url in targets:
        resp = client.get(url)
        if not resp.ok:
            continue
        haystack = resp.header("set-cookie") + "\n" + (resp.header("authorization") or "")
        haystack += "\n" + resp.text
        for token in find_jwts(haystack):
            tokens.setdefault(token, url)
    return tokens


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    tokens = _collect_tokens(result, client)
    if not tokens:
        return []
    ui.info(f"Analyzing {len(tokens)} JWT(s)…")

    findings: list[Finding] = []
    for token, url in tokens.items():
        for issue in analyze(token):
            findings.append(
                Finding(
                    title=issue["title"],
                    severity=issue["severity"],
                    target=result.target.host,
                    category=f"jwt-{issue['kind']}",
                    location=url,
                    description=issue["description"],
                    remediation=issue["remediation"],
                    evidence=issue["evidence"],
                    source=_SOURCE,
                    extra={"token_prefix": token[:16]},
                )
            )
    return findings
