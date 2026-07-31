"""Unit tests for the SSRF and Host-header injection checks."""

from __future__ import annotations

import requests

from strix.models import ScanResult, Target
from strix.scan import hostheader, ssrf


# --- Host-header injection ------------------------------------------------- #
def test_hostheader_redirect_reflection():
    loc = f"https://{hostheader._MARK}/login"
    assert hostheader.analyze("https://a.com", "Host", loc, "") == "redirect"


def test_hostheader_body_reflection():
    body = f'<a href="https://{hostheader._MARK}/reset?token=x">reset</a>'
    assert hostheader.analyze("https://a.com", "X-Forwarded-Host", "", body) == "body"


def test_hostheader_no_reflection():
    assert hostheader.analyze("https://a.com", "Host", "https://a.com/x", "hello") == ""


# --- SSRF helpers ---------------------------------------------------------- #
def test_looks_like_url():
    assert ssrf._looks_like_url("https://x") and ssrf._looks_like_url("//x")
    assert not ssrf._looks_like_url("hello")


def test_signature_match_substr_and_regex():
    assert ssrf._signature_match("...instance-id...", ("instance-id",), None)
    assert ssrf._signature_match("root:x:0:0:root:/root", (), r"root:.*:0:0:")
    assert not ssrf._signature_match("nothing here", ("ami-id",), r"root:.*:0:0:")


def test_ssrf_candidates_selects_url_params_in_scope():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="http://a.com"))
    r.urls = [
        "http://a.com/f?url=http://x",     # url param -> candidate
        "http://a.com/p?id=1",             # not a fetch param, non-url value -> skip
        "http://a.com/g?next=//evil",      # value looks like url -> candidate
        "http://evil.com/f?url=http://x",  # out of scope -> skip
    ]
    pairs = ssrf._candidates(r, cap=50)
    hosts_params = {(u.split("/")[2], p) for u, p in pairs}
    assert ("a.com", "url") in hosts_params
    assert ("a.com", "next") in hosts_params
    assert all(host == "a.com" for host, _ in hosts_params)  # evil.com excluded
    assert ("a.com", "id") not in hosts_params


def test_oob_listener_records_callback():
    listener = ssrf.OOBListener(bind_host="127.0.0.1", port=0)
    listener.start()
    try:
        requests.get(f"http://127.0.0.1:{listener.port}/tok12345", timeout=5)
        assert listener.got("tok12345")
        assert not listener.got("never")
    finally:
        listener.stop()
