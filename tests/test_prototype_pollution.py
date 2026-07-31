"""Unit tests for the server-side prototype pollution check."""

from __future__ import annotations

import json

from strix.models import ScanResult, Target, WebEndpoint
from strix.scan import prototype_pollution as pp
from strix.utils.net import HttpResponse


def test_pollute_body():
    assert json.loads(pp._pollute_body(10)) == {"__proto__": {"json spaces": 10}}


def test_became_indented():
    compact = '{"a":1,"b":2}'
    indented = '{\n' + ' ' * 10 + '"a": 1,\n' + ' ' * 10 + '"b": 2\n}'
    assert pp.became_indented(compact, indented) is True
    assert pp.became_indented(compact, compact) is False
    # Already indented at baseline -> not attributable to us.
    assert pp.became_indented(indented, indented) is False
    assert pp.became_indented(compact, "<html>not json</html>") is False


def test_candidates_prefers_json_and_api():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    r.endpoints = [WebEndpoint(url="https://a.com/data", status=200, content_type="application/json")]
    r.urls = ["https://a.com/api/users", "https://evil.com/api/x"]
    urls = pp._candidates(r, cap=20)
    assert "https://a.com/data" in urls
    assert "https://a.com/api/users" in urls
    assert not any("evil.com" in u for u in urls)


def test_check_detects_sspp_via_state():
    r = ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))
    r.endpoints = [WebEndpoint(url="https://a.com/api", status=200, content_type="application/json")]

    class Client:
        def __init__(self):
            self.spaces = 0

        def request(self, method, url, headers=None, data=None, allow_redirects=True):
            # Simulate a vulnerable merge: pollution sets the global json spaces.
            if data and "__proto__" in data:
                self.spaces = json.loads(data)["__proto__"]["json spaces"]
            return HttpResponse(url=url, ok=True, status=200, headers={}, text="{}")

        def get(self, url, **kwargs):
            obj = {"user": "a", "role": "admin"}
            text = json.dumps(obj, indent=self.spaces) if self.spaces else json.dumps(obj)
            return HttpResponse(url=url, ok=True, status=200, headers={}, text=text)

    class UI:
        def info(self, m): pass

    findings = pp.check(r, None, Client(), UI())
    assert len(findings) == 1
    assert findings[0].category == "prototype-pollution"
    assert findings[0].severity.name == "HIGH"
