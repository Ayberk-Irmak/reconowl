"""Unit tests for DNS helpers that do not require network."""

from __future__ import annotations

from reconowl.utils import dnsx


def test_is_ip_literal():
    assert dnsx._is_ip_literal("192.168.1.1") is True
    assert dnsx._is_ip_literal("2001:db8::1") is True
    assert dnsx._is_ip_literal("example.com") is False


def test_getaddrinfo_override_passthrough_for_ip(monkeypatch):
    # For an IP literal the override must defer to the original resolver.
    called = {}

    def fake_orig(host, port, *a, **k):
        called["host"] = host
        return [("fam", "type", "proto", "", (host, port))]

    monkeypatch.setattr(dnsx, "_orig_getaddrinfo", fake_orig)
    res = dnsx._resolving_getaddrinfo("10.0.0.1", 80)
    assert called["host"] == "10.0.0.1"
    assert res[0][4] == ("10.0.0.1", 80)


def test_getaddrinfo_override_uses_cache(monkeypatch):
    monkeypatch.setattr(dnsx, "_addr_cache", {"host.test": ["9.9.9.9"]})
    res = dnsx._resolving_getaddrinfo("host.test", 443)
    assert res == [(dnsx.socket.AF_INET, dnsx.socket.SOCK_STREAM,
                    dnsx.socket.IPPROTO_TCP, "", ("9.9.9.9", 443))]
