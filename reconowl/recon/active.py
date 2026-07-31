"""Active reconnaissance — direct interaction with the target.

Port/service discovery (nmap when present, native TCP connect scan otherwise),
HTTP probing (httpx when present, native ``requests`` otherwise), TLS/certificate
inspection, and lightweight content discovery (robots.txt, sitemap.xml).
"""

from __future__ import annotations

import socket
import urllib.parse

from ..config import ScanConfig
from ..external import httpx_tool, nmap
from ..models import Port, ScanResult, WebEndpoint
from ..utils import tlsx
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_client


# --- Port scanning --------------------------------------------------------- #
def _native_port_scan(host: str, ports: list[int], workers: int, timeout: float) -> list[Port]:
    """Fallback TCP connect scan when nmap is unavailable."""
    def probe(port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=min(timeout, 3.0)):
                return True
        except OSError:
            return False

    open_ports: list[Port] = []
    for port, is_open in parallel_map(probe, ports, workers=workers):
        if is_open:
            service = _GUESS_SERVICE.get(port, "")
            open_ports.append(Port(number=port, service=service))
    return sorted(open_ports, key=lambda p: p.number)


_GUESS_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def _scan_ports(result: ScanResult, config: ScanConfig, ui) -> None:
    host = result.target.ip or result.target.host
    if config.use_external and nmap.available():
        ui.info(f"Port/service scan with nmap ({config.port_spec()})…")
        ports, _raw = nmap.scan(host, config.port_spec(), extra=config.nmap_extra)
        result.tools_used["nmap"] = "port scan"
    else:
        ui.info("Port scan with native TCP connect scanner…")
        ports = _native_port_scan(host, config.native_ports(), config.concurrency, config.timeout)
    result.ports = ports
    if ports:
        ui.good(
            "Open ports: "
            + ", ".join(f"{p.number}/{p.service or p.protocol}" for p in ports)
        )
    else:
        ui.warn("No open ports found (host may be filtered).")


# --- Web probing ----------------------------------------------------------- #
def _candidate_web_urls(result: ScanResult) -> list[str]:
    """Base URLs to probe: scheme://host on any HTTP-ish open port."""
    host = result.target.host
    urls: set[str] = set()
    web_ports = {80: "http", 443: "https", 8080: "http", 8443: "https", 8000: "http", 8888: "http"}
    for port in result.ports:
        scheme = web_ports.get(port.number)
        if scheme:
            netloc = host if port.number in (80, 443) else f"{host}:{port.number}"
            urls.add(f"{scheme}://{netloc}")
    if not urls:
        # No scan data (e.g. passive-only host): try the obvious two.
        urls.update({f"https://{host}", f"http://{host}"})
    if result.target.base_url:
        urls.add(result.target.base_url)
    return sorted(urls)


def _native_probe(client: HttpClient, url: str) -> WebEndpoint | None:
    resp = client.get(url)
    if not resp.ok:
        return None
    title = _extract_title(resp.text)
    return WebEndpoint(
        url=url,
        status=resp.status,
        title=title,
        server=resp.header("Server"),
        content_type=resp.header("Content-Type").split(";")[0],
        content_length=int(resp.header("Content-Length")) if resp.header("Content-Length").isdigit() else None,
        redirect=resp.final_url if resp.final_url and resp.final_url != url else "",
    )


def _extract_title(html: str) -> str:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


def _probe_web(result: ScanResult, config: ScanConfig, ui) -> None:
    candidates = _candidate_web_urls(result)
    ui.info(f"Probing {len(candidates)} web endpoint(s)…")

    endpoints: list[WebEndpoint] = []
    if config.use_external and httpx_tool.available():
        endpoints = httpx_tool.probe(candidates, headers=config.build_headers())
        if endpoints:
            result.tools_used["httpx"] = "web probing"

    # Fall back to (or start with) the native prober if httpx is absent or, for
    # whatever reason, returned nothing — so a probe result is never silently lost.
    if not endpoints:
        client = build_client(config)
        for _url, ep in parallel_map(lambda u: _native_probe(client, u), candidates, workers=config.concurrency):
            if ep is not None:
                endpoints.append(ep)

    result.endpoints = endpoints
    techs: set[str] = set()
    for ep in endpoints:
        techs.update(ep.technologies)
        ui.good(f"{ep.status} {ep.url}  {('· ' + ep.title) if ep.title else ''}")
    result.technologies = sorted(techs)

    # Pick a primary base URL for later phases.
    if endpoints and not result.target.base_url:
        best = sorted(endpoints, key=lambda e: (e.url.startswith("https"), e.status == 200), reverse=True)[0]
        result.target.base_url = best.url


# --- TLS ------------------------------------------------------------------- #
def _inspect_tls(result: ScanResult, config: ScanConfig, ui) -> None:
    has_tls = any(p.number in (443, 8443) for p in result.ports) or not result.ports
    if not has_tls:
        return
    ui.info("Inspecting TLS certificate…")
    info = tlsx.inspect(result.target.host, 443, timeout=config.timeout, ip=result.target.ip)
    if info.get("error"):
        return
    result.tls = info
    # Certificate SANs are a cheap subdomain source.
    for san in info.get("sans", []):
        san = san.lstrip("*.").lower()
        if san.endswith(result.target.host.lower()) and san not in result.subdomains:
            result.subdomains.append(san)
    result.subdomains = sorted(set(result.subdomains))
    if info.get("subject_cn"):
        trust = "trusted" if info.get("trusted") else "UNTRUSTED"
        ui.good(f"TLS: {info.get('protocol')} · CN={info['subject_cn']} · {trust}")


# --- Content discovery ----------------------------------------------------- #
def _content_discovery(result: ScanResult, config: ScanConfig, ui) -> None:
    base = result.target.base_url
    if not base:
        return
    client = build_client(config)

    # robots.txt often reveals interesting disallowed paths.
    robots = client.get(urllib.parse.urljoin(base + "/", "robots.txt"))
    if robots.ok and robots.status == 200 and "Disallow" in robots.text:
        paths = [
            line.split(":", 1)[1].strip()
            for line in robots.text.splitlines()
            if line.lower().startswith("disallow") and ":" in line
        ]
        for p in paths:
            if p and p != "/":
                full = urllib.parse.urljoin(base + "/", p.lstrip("/"))
                if full not in result.urls:
                    result.urls.append(full)
        if paths:
            ui.good(f"robots.txt: {len([p for p in paths if p])} disallowed path(s)")

    # sitemap.xml enumerates real URLs.
    sitemap = client.get(urllib.parse.urljoin(base + "/", "sitemap.xml"))
    if sitemap.ok and sitemap.status == 200:
        import re

        locs = re.findall(r"<loc>\s*([^<]+?)\s*</loc>", sitemap.text)
        added = 0
        for loc in locs:
            if loc not in result.urls:
                result.urls.append(loc.strip())
                added += 1
        if added:
            ui.good(f"sitemap.xml: {added} URL(s)")


def run(result: ScanResult, config: ScanConfig, ui, *, web_only: bool = False) -> None:
    """Run active recon, populating ports, endpoints, TLS and URLs.

    ``web_only`` skips port scanning and goes straight to the web layer — used
    when deepening into many subdomains, where a full port sweep per host would
    be prohibitively slow.
    """
    if not result.target.ip:
        from ..utils import dnsx

        result.target.ip = dnsx.resolve_ip(result.target.host)

    if not web_only:
        _scan_ports(result, config, ui)
    _probe_web(result, config, ui)
    _inspect_tls(result, config, ui)
    _content_discovery(result, config, ui)
    if not web_only:
        from . import crawler, jsanalysis

        crawler.run(result, config, ui)
        jsanalysis.run(result, config, ui)
