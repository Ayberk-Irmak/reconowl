"""Unit tests for authenticated scanning (headers/cookie/bearer/basic)."""

from __future__ import annotations

import argparse
import base64

from reconowl.cli import build_auth_headers
from reconowl.config import ScanConfig
from reconowl.utils.net import HttpClient, build_client
from reconowl.utils.tools import header_flags


def _args(**kw):
    ns = argparse.Namespace(header=None, bearer="", auth_basic="", cookie="")
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_build_auth_headers_custom_and_bearer():
    h = build_auth_headers(_args(header=["X-Api-Key: abc", "X-Env: prod"], bearer="tok"))
    assert h["X-Api-Key"] == "abc"
    assert h["X-Env"] == "prod"
    assert h["Authorization"] == "Bearer tok"


def test_build_auth_headers_basic():
    h = build_auth_headers(_args(auth_basic="admin:s3cr3t"))
    expected = "Basic " + base64.b64encode(b"admin:s3cr3t").decode()
    assert h["Authorization"] == expected


def test_config_build_headers_includes_cookie():
    cfg = ScanConfig(extra_headers={"Authorization": "Bearer x"}, cookie="session=1; role=admin")
    headers = cfg.build_headers()
    assert headers["Authorization"] == "Bearer x"
    assert headers["Cookie"] == "session=1; role=admin"
    assert cfg.is_authenticated() is True
    assert ScanConfig().is_authenticated() is False


def test_build_client_applies_headers_to_session():
    cfg = ScanConfig(extra_headers={"Authorization": "Bearer xyz"}, cookie="s=1")
    client = build_client(cfg)
    assert client._session.headers["Authorization"] == "Bearer xyz"
    assert client._session.headers["Cookie"] == "s=1"


def test_httpclient_no_headers_ok():
    client = HttpClient()
    assert "Authorization" not in client._session.headers


def test_header_flags():
    flags = header_flags({"Authorization": "Bearer t", "X-Env": "prod"})
    assert flags == ["-H", "Authorization: Bearer t", "-H", "X-Env: prod"]
    assert header_flags({}) == []
