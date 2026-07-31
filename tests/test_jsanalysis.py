"""Unit tests for JS endpoint/secret extraction and the secrets check."""

from __future__ import annotations

from reconowl.models import ScanResult, Severity, Target
from reconowl.recon import jsanalysis
from reconowl.scan import secrets as secrets_check


def test_extract_endpoints_in_scope_only():
    js = """
      fetch("/api/v1/users?id=1");
      const u = "https://app.example.com/admin/panel";
      var x = "https://cdn.other.com/lib.js";
      img.src = "/static/logo.png";
    """
    eps = jsanalysis.extract_endpoints(js, "https://app.example.com/app.js", "app.example.com")
    assert "https://app.example.com/api/v1/users?id=1" in eps
    assert "https://app.example.com/admin/panel" in eps
    assert not any("other.com" in e for e in eps)     # out of scope
    assert not any(e.endswith(".png") for e in eps)   # static asset skipped


def test_extract_secrets_high_signal():
    js = """
      const AWS = "AKIA1234567890ABCDEF";
      var g = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
      github = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
      key = "-----BEGIN RSA PRIVATE KEY-----";
    """
    hits = jsanalysis.extract_secrets(js, "https://a.com/app.js")
    types = {h["type"] for h in hits}
    assert "AWS Access Key ID" in types
    assert "Google API Key" in types
    assert "GitHub Token" in types
    assert "Private Key" in types
    # values are redacted, not shown in full
    aws = next(h for h in hits if h["type"] == "AWS Access Key ID")
    assert "…" in aws["match"] and "AKIA1234567890ABCDEF" not in aws["match"]


def test_extract_secrets_skips_placeholders():
    js = 'apiKey: "your_api_key_here", token: "REPLACE_ME_EXAMPLE"'
    hits = jsanalysis.extract_secrets(js, "u")
    assert hits == []


def test_generic_api_key_captured():
    js = 'const cfg = { client_secret: "a1b2c3d4e5f6g7h8i9j0" };'
    hits = jsanalysis.extract_secrets(js, "u")
    assert any(h["type"] == "Generic API key/secret" for h in hits)


def test_secrets_check_builds_findings():
    r = ScanResult(target=Target(raw="a.com", host="a.com"))
    r.secrets = [
        {"type": "AWS Access Key ID", "match": "AKIA…X2", "severity": "High",
         "location": "https://a.com/app.js"},
    ]
    findings = secrets_check.check(r, None, None, None)
    assert len(findings) == 1
    assert findings[0].category == "exposed-secret"
    assert findings[0].severity is Severity.HIGH
    assert "AWS" in findings[0].title
