"""Unit tests for the OS command injection check."""

from __future__ import annotations

from reconowl.config import ScanConfig
from reconowl.models import ScanResult, Target
from reconowl.scan import cmdinjection as cmdi
from reconowl.utils.net import HttpResponse


def test_detect_output_id_pattern():
    assert cmdi.detect_output("uid=0(root) gid=0(root) groups=0(root)") == "id -> uid/gid"


def test_detect_output_arithmetic():
    assert cmdi.detect_output("result: 1022117 done") == "arithmetic -> 1022117"


def test_detect_output_negative_and_baseline():
    assert cmdi.detect_output("nothing here") is None
    # payload reflected literally (contains the expression, not the product)
    assert cmdi.detect_output("echo CMDi$((1009*1013))CMDi") is None
    # product already in baseline -> not attributable
    assert cmdi.detect_output("1022117", baseline="1022117") is None


def test_candidates_in_scope_and_base_probes():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/p?host=1", "http://evil.com/p?host=1"]
    pairs = cmdi._candidates(r, cap=50)
    assert not any("evil.com" in u for u, _ in pairs)
    assert "host" in {p for _, p in pairs}


def test_check_detects_output_based():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))

    class Client:
        def get(self, url, allow_redirects=True, **kwargs):
            # Simulate execution of `id` when an id payload is injected.
            if "id" in url and ("%3B" in url or "%60" in url or "%24" in url):
                return HttpResponse(url=url, ok=True, status=200, headers={},
                                    text="uid=33(www-data) gid=33(www-data) groups=33")
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="normal")

    class UI:
        def info(self, m): pass

    # timeout < sleep+2 so the (network-timing) branch is skipped -> deterministic.
    findings = cmdi.check(r, ScanConfig(timeout=5), Client(), UI())
    assert findings and findings[0].category == "command-injection"
    assert findings[0].severity.name == "CRITICAL"
    assert "uid/gid" in findings[0].evidence
