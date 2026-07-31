"""Resilient DNS resolution.

Tries the system resolver first (fast when the network allows UDP/53), then
falls back to DNS-over-HTTPS. DoH means Strix still resolves names in locked-down
environments that only permit outbound HTTPS — a common reality on jump hosts and
restricted testing VLANs.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.parse
import urllib.request

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

# DNS record type name -> numeric code (to filter DoH answers).
_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}

_DOH_PROVIDERS = (
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
)


def _system_resolve(host: str, rtype: str, timeout: float) -> list[str] | None:
    """Query the OS resolver via dnspython. None means it failed (try DoH)."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(host, rtype)
        return sorted(str(r.to_text()) for r in answers)
    except Exception:  # noqa: BLE001 - NXDOMAIN, timeout, no-record all -> None
        return None


def _doh_resolve(host: str, rtype: str, timeout: float) -> list[str]:
    """Resolve a single record type via DNS-over-HTTPS (JSON API)."""
    want = _TYPE_NUM.get(rtype)
    for provider in _DOH_PROVIDERS:
        url = provider + "?" + urllib.parse.urlencode({"name": host, "type": rtype})
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "strix/0.1", "Accept": "application/dns-json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - try the next provider
            continue
        answers = data.get("Answer") or []
        values = [
            str(a.get("data", "")).strip()
            for a in answers
            if want is None or a.get("type") == want
        ]
        values = [v for v in values if v]
        if values or "Answer" in data:
            return sorted(set(values))
    return []


def resolve(host: str, rtype: str, timeout: float = 3.0) -> list[str]:
    """Resolve one record type.

    DoH is tried first: it is fast and works wherever outbound HTTPS does. Only
    when DoH yields nothing (e.g. an internal name public resolvers can't see) do
    we fall back to the OS resolver, with a short timeout so a blocked UDP/53 path
    never stalls the scan.
    """
    doh = _doh_resolve(host, rtype, timeout)
    if doh:
        return doh
    return _system_resolve(host, rtype, min(timeout, 1.5)) or []


def resolve_records(host: str, timeout: float = 3.0) -> dict[str, list[str]]:
    """Resolve the common record set, dropping types with no data."""
    records: dict[str, list[str]] = {}
    for rtype in _RECORD_TYPES:
        values = resolve(host, rtype, timeout=timeout)
        if values:
            records[rtype] = values
    return records


def resolve_ip(host: str, timeout: float = 3.0) -> str:
    """First A record for ``host``, or empty string."""
    a = resolve(host, "A", timeout=timeout)
    return a[0] if a else ""


# --- DoH-backed socket resolution ----------------------------------------- #
# When the OS resolver can't reach UDP/53 (locked-down egress, broken resolv.conf)
# every requests/socket call would fail. Installing a DoH-first getaddrinfo makes
# the whole stack resolve over HTTPS instead. Off by default so internal/split-
# horizon DNS stays correct; enabled explicitly or when the OS path is unhealthy.

_orig_getaddrinfo = socket.getaddrinfo
_addr_cache: dict[str, list[str]] = {}
#: "smart" = OS resolver first (time-bounded) then DoH; "doh" = DoH first.
_mode = "smart"


def _is_ip_literal(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def _system_addrs(host: str, timeout: float = 2.0) -> list[str]:
    """Time-bounded OS resolution to IPv4 addresses (empty on failure/timeout).

    getaddrinfo has no timeout, so it runs in a daemon thread we abandon if it
    stalls — abandoning is safe because the thread is a daemon and results are
    only used if they arrive in time.
    """
    box: dict[str, list[str]] = {}

    def _q() -> None:
        try:
            infos = _orig_getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            box["ips"] = [i[4][0] for i in infos]
        except OSError:
            box["ips"] = []

    thread = threading.Thread(target=_q, daemon=True)
    thread.start()
    thread.join(timeout)
    return box.get("ips", [])


def _addrs(host: str) -> list[str]:
    ips = _addr_cache.get(host)
    if ips is not None:
        return ips
    if _mode == "smart":
        ips = _system_addrs(host) or _doh_resolve(host, "A", 5.0)
    else:  # doh-first
        ips = _doh_resolve(host, "A", 5.0) or _system_addrs(host)
    _addr_cache[host] = ips
    return ips


def _resolving_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
    """getaddrinfo replacement that resolves names via DoH when the OS can't."""
    if not isinstance(host, str) or _is_ip_literal(host):
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    ips = _addrs(host)
    if not ips:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    sock_type = type or socket.SOCK_STREAM
    port_num = port if isinstance(port, int) else (int(port) if str(port).isdigit() else 0)
    return [
        (socket.AF_INET, sock_type, proto or socket.IPPROTO_TCP, "", (ip, port_num))
        for ip in ips
    ]


def system_healthy(timeout: float = 2.0) -> bool:
    """True if the OS resolver answers a known name within ``timeout``."""
    return bool(_system_addrs("cloudflare.com", timeout=timeout))


def enable_doh_socket(mode: str = "smart") -> None:
    """Route socket name resolution through the resilient resolver (idempotent).

    ``mode="smart"`` tries the OS resolver first (correct for internal/split-
    horizon names) then DoH; ``mode="doh"`` prefers DoH (fastest on locked-down
    egress or when the OS resolver is unreliable).
    """
    global _mode
    _mode = mode if mode in ("smart", "doh") else "smart"
    socket.getaddrinfo = _resolving_getaddrinfo


def disable_doh_socket() -> None:
    """Restore the original OS resolver."""
    socket.getaddrinfo = _orig_getaddrinfo
