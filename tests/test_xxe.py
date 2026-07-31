"""Unit tests for the XXE check."""

from __future__ import annotations

from reconowl.config import ScanConfig
from reconowl.models import ScanResult, Target, WebEndpoint
from reconowl.scan import xxe
from reconowl.utils.net import HttpResponse


def test_payloads_contain_entities():
    assert 'SYSTEM "file:///etc/passwd"' in xxe.inband_payload()
    assert "&xxe;" in xxe.inband_payload()
    oob = xxe.oob_payload("http://10.0.0.1:9000/tok")
    assert 'SYSTEM "http://10.0.0.1:9000/tok"' in oob


def test_detect_inband():
    assert xxe.detect_inband("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    assert not xxe.detect_inband("nothing sensitive here")
    assert not xxe.detect_inband("")


def test_candidates_in_scope_and_common_paths():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    r.endpoints = [WebEndpoint(url="https://a.com/soap/service", status=200),
                   WebEndpoint(url="https://evil.com/x", status=200)]
    urls = xxe._candidates(r, cap=30)
    assert "https://a.com/xmlrpc.php" in urls
    assert "https://a.com/soap/service" in urls
    assert not any("evil.com" in u for u in urls)  # out of scope excluded


def test_check_detects_inband_file_read():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))

    class Client:
        def request(self, method, url, headers=None, data=None, allow_redirects=True):
            if url.endswith("/xmlrpc.php") and "file:///etc/passwd" in data:
                return HttpResponse(url=url, ok=True, status=200, headers={},
                                    text="<root>root:x:0:0:root:/root:/bin/bash</root>")
            return HttpResponse(url=url, ok=True, status=404, headers={}, text="no")

    class UI:
        def info(self, m): pass
        def warn(self, m): pass

    # OOB off so the test is deterministic and offline.
    findings = xxe.check(r, ScanConfig(ssrf_oob=False), Client(), UI())
    assert len(findings) == 1
    assert findings[0].category == "xxe"
    assert "file disclosure" in findings[0].title
    assert findings[0].target == "a.com"
