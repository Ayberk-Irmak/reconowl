"""Unit tests for the subdomain-takeover check."""

from __future__ import annotations

from reconowl.models import ScanResult, Target
from reconowl.scan import takeover
from reconowl.utils.net import HttpResponse

_FPS = [
    {"service": "GitHub Pages", "cnames": ["github.io"],
     "fingerprint": "There isn't a GitHub Pages site here.", "unique": True, "nxdomain": False},
    {"service": "Heroku", "cnames": ["herokuapp.com"], "fingerprint": "No such app",
     "unique": False, "nxdomain": True},
    {"service": "Strikingly", "cnames": ["strikinglydns.com"], "fingerprint": "page not found",
     "unique": False, "nxdomain": False},
    {"service": "Azure", "cnames": ["azurewebsites.net"], "fingerprint": "", "unique": False, "nxdomain": True},
]


def test_builtin_fingerprints_load():
    fps = takeover.load_fingerprints()
    assert len(fps) > 10
    assert any(f["service"] == "GitHub Pages" for f in fps)


def test_analyze_fingerprint_match_wins():
    out = takeover.analyze(
        ["myapp.github.io"], "Oops. There isn't a GitHub Pages site here.", True, _FPS
    )
    assert out == ("GitHub Pages", "fingerprint")


def test_analyze_dangling_cname_when_unresolvable():
    out = takeover.analyze(["myapp.azurewebsites.net"], "", False, _FPS)
    assert out == ("Azure", "dangling-cname")


def test_analyze_resolvable_service_without_fingerprint_is_none():
    # Points at Azure but still resolves and no fingerprint -> not a candidate.
    assert takeover.analyze(["x.azurewebsites.net"], "welcome", True, _FPS) is None


def test_analyze_unrelated_is_none():
    assert takeover.analyze(["cdn.cloudflare.net"], "hello world", True, _FPS) is None


def test_analyze_generic_fingerprint_needs_cname_match():
    # "page not found" is generic: a matching body but unrelated CNAME must NOT flag.
    assert takeover.analyze(["cdn.example.net"], "404 page not found", True, _FPS) is None
    # Same body but the CNAME points at Strikingly -> now it's a real candidate.
    out = takeover.analyze(["x.strikinglydns.com"], "404 page not found", True, _FPS)
    assert out == ("Strikingly", "fingerprint")


def test_check_detects_github_takeover(monkeypatch):
    result = ScanResult(target=Target(raw="example.com", host="example.com"))
    result.subdomains = ["blog.example.com"]

    monkeypatch.setattr(takeover, "load_fingerprints", lambda path="": _FPS)
    monkeypatch.setattr(
        takeover.dnsx, "resolve",
        lambda host, rtype, **k: ["blog.example.com.github.io"] if rtype == "CNAME" else [],
    )
    monkeypatch.setattr(takeover.dnsx, "resolve_ip", lambda host, **k: "185.199.108.153")

    class Client:
        def get(self, url, **kwargs):
            if url.startswith("https://blog.example.com"):
                return HttpResponse(url=url, ok=True, status=404,
                                    headers={}, text="404 There isn't a GitHub Pages site here.")
            return HttpResponse(url=url, ok=False, error="x")

    class UI:
        def info(self, m): pass

    findings = takeover.check(result, _cfg(), Client(), UI())
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "subdomain-takeover"
    assert "GitHub Pages" in f.title
    assert f.location == "blog.example.com"


def _cfg():
    from reconowl.config import ScanConfig
    return ScanConfig(concurrency=4)
