"""Unit tests for the LFI / path traversal check."""

from __future__ import annotations

from strix.models import ScanResult, Target
from strix.scan import lfi
from strix.utils.net import HttpResponse


def test_detect_linux_passwd():
    assert lfi.detect("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:") == "linux:/etc/passwd"


def test_detect_windows_ini():
    assert lfi.detect("; for 16-bit app support\n[fonts]\n") == "windows:win.ini"


def test_detect_negative_and_baseline():
    assert lfi.detect("nothing here") is None
    # Signature already in baseline -> not attributable to us.
    assert lfi.detect("root:x:0:0:", baseline="root:x:0:0:") is None


def test_candidates_in_scope_and_base_probes():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/dl?file=a.pdf", "http://evil.com/dl?file=x"]
    pairs = lfi._candidates(r, cap=50)
    assert not any("evil.com" in u for u, _ in pairs)
    params = {p for _, p in pairs}
    assert "file" in params


def test_check_detects_traversal():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))

    class Client:
        def get(self, url, allow_redirects=True, **kwargs):
            if "passwd" in url or "%2fpasswd" in url or "%252f" in url:
                return HttpResponse(url=url, ok=True, status=200, headers={},
                                    text="root:x:0:0:root:/root:/bin/bash")
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="normal page")

    class UI:
        def info(self, m): pass

    from strix.config import ScanConfig
    findings = lfi.check(r, ScanConfig(), Client(), UI())
    assert findings and findings[0].category == "lfi"
    assert findings[0].severity.name == "HIGH"
    assert "linux:/etc/passwd" in findings[0].evidence
