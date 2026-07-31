"""Unit tests for the NoSQL injection check."""

from __future__ import annotations

from reconowl.config import ScanConfig
from reconowl.models import ScanResult, Target
from reconowl.scan import nosqli
from reconowl.utils.net import HttpResponse


def test_detect_error_signatures():
    assert nosqli.detect_error("MongoError: unknown operator: $foo") == "mongoerror"
    assert nosqli.detect_error("E11000 duplicate key") == "e11000"
    assert nosqli.detect_error("normal page") is None
    # signature already present in baseline -> not attributable
    assert nosqli.detect_error("MongoError", baseline="MongoError seen") is None


def test_significant_diff():
    big = HttpResponse(url="u", ok=True, status=200, text="x" * 1000)
    small = HttpResponse(url="u", ok=True, status=200, text="x" * 100)
    same = HttpResponse(url="u", ok=True, status=200, text="x" * 1000)
    assert nosqli.significant_diff(big, small) is True
    assert nosqli.significant_diff(big, same) is False
    # status-class difference also counts
    err = HttpResponse(url="u", ok=True, status=500, text="x" * 1000)
    assert nosqli.significant_diff(big, err) is True


def test_set_bracket():
    out = nosqli._set_bracket("http://a/s?name=bob&x=1", "name", "ne", "R")
    assert "name%5B%24ne%5D=R" in out
    assert "x=1" in out
    assert "name=bob" not in out


def test_check_error_based():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/search?name=bob"]

    class Client:
        def get(self, url, allow_redirects=True, **kwargs):
            if "%27" in url or "%22" in url:  # a quote payload
                return HttpResponse(url=url, ok=True, status=500, headers={},
                                    text="MongoError: unterminated string")
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="one result")

    class UI:
        def info(self, m): pass

    findings = nosqli.check(r, ScanConfig(), Client(), UI())
    assert any(f.category == "nosql-injection" and "error-based" in f.title for f in findings)


def test_check_operator_differential():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = ["http://a.com/find?q=x"]

    class Client:
        def get(self, url, allow_redirects=True, **kwargs):
            if "%24ne%5D" in url:            # [$ne] -> matches everything (big)
                return HttpResponse(url=url, ok=True, status=200, headers={}, text="R" * 2000)
            if "%24eq%5D" in url:            # [$eq] -> matches nothing (small)
                return HttpResponse(url=url, ok=True, status=200, headers={}, text="none")
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="one")

    class UI:
        def info(self, m): pass

    findings = nosqli.check(r, ScanConfig(), Client(), UI())
    assert any("operator" in f.title for f in findings)
