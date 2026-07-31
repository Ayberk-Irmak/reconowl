"""Unit tests for the default/weak-credentials check."""

from __future__ import annotations

import base64

from reconowl.config import ScanConfig
from reconowl.models import ScanResult, Target, WebEndpoint
from reconowl.scan import default_creds
from reconowl.utils.net import HttpResponse


def _result():
    return ScanResult(target=Target(raw="a.com", host="a.com", base_url="https://a.com"))


class _UI:
    def good(self, m): pass
    def warn(self, m): pass
    def info(self, m): pass


def test_login_success_discriminates_baseline():
    login_page = '<form><input type="password" name="p"></form>'
    dashboard = "<html>Welcome — <a href=/logout>Logout</a></html>"
    # Wrong creds keep us on the login page; right creds reach the dashboard.
    assert default_creds.login_success(login_page, dashboard) is True
    assert default_creds.login_success(login_page, login_page) is False


def test_basic_auth_default_creds_detected():
    cfg = ScanConfig(target="a.com")
    result = _result()
    result.endpoints.append(WebEndpoint(url="https://a.com/admin"))

    good = base64.b64encode(b"admin:admin").decode()

    class Client:
        def get(self, url, headers=None, **k):
            if not url.endswith("/admin"):  # only /admin is a Basic-Auth realm
                return HttpResponse(url=url, ok=True, status=404, headers={})
            auth = (headers or {}).get("Authorization", "")
            if not auth:
                return HttpResponse(url=url, ok=True, status=401,
                                    headers={"WWW-Authenticate": "Basic realm=x"})
            if auth == f"Basic {good}":
                return HttpResponse(url=url, ok=True, status=200, headers={}, text="secret")
            return HttpResponse(url=url, ok=True, status=401, headers={})

    findings = default_creds._basic_auth_check(result, cfg, Client(), _UI())
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "default-credentials"
    assert f.severity.name == "CRITICAL"
    assert "admin:admin" in f.title


def test_basic_auth_no_hit_when_all_rejected():
    cfg = ScanConfig(target="a.com")
    result = _result()
    result.endpoints.append(WebEndpoint(url="https://a.com/admin"))

    class Client:
        def get(self, url, headers=None, **k):
            if not url.endswith("/admin"):
                return HttpResponse(url=url, ok=True, status=404, headers={})
            if not (headers or {}).get("Authorization"):
                return HttpResponse(url=url, ok=True, status=401,
                                    headers={"WWW-Authenticate": "Basic"})
            return HttpResponse(url=url, ok=True, status=401, headers={})

    assert default_creds._basic_auth_check(result, cfg, Client(), _UI()) == []


def test_disabled_via_config():
    cfg = ScanConfig(target="a.com", default_creds=False)
    assert default_creds.check(_result(), cfg, object(), _UI()) == []
