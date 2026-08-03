"""Subdomain deepening.

When ``--subdomains`` is set, take the subdomains found during passive recon,
keep the ones that are actually live, and run a web-layer scan (probe + TLS +
every native web vulnerability check) against each — merging their endpoints and
findings back into the main result. Port scanning and nuclei are skipped per
subdomain to keep a broad sweep practical; the primary host still gets both.
"""

from __future__ import annotations

import time
from dataclasses import replace

from .config import ScanConfig
from .models import ScanResult, Target
from .recon import active
from .scan import engine
from .utils import dnsx
from .utils.concurrency import parallel_map
from .utils.net import HttpClient, build_client


class _QuietUI:
    """A UI shim that mutes progress chatter but still surfaces findings/errors."""

    def __init__(self, ui) -> None:
        self._ui = ui
        self.quiet = True

    def info(self, msg: str) -> None:  # noqa: D102
        pass

    def good(self, msg: str) -> None:  # noqa: D102
        pass

    def phase(self, name: str) -> None:  # noqa: D102
        pass

    def warn(self, msg: str) -> None:  # noqa: D102
        self._ui.warn(msg)

    def error(self, msg: str) -> None:  # noqa: D102
        self._ui.error(msg)

    def finding(self, severity, title, location="") -> None:  # noqa: D102
        self._ui.finding(severity, title, location)


def _live_subdomains(subs: list[str], client: HttpClient, workers: int) -> dict[str, str]:
    """Return {subdomain: base_url} for those that answer over HTTPS or HTTP."""
    def probe(sub: str) -> str | None:
        for scheme in ("https", "http"):
            resp = client.get(f"{scheme}://{sub}", allow_redirects=True)
            if resp.ok and resp.status:
                return f"{scheme}://{sub}"
        return None

    live: dict[str, str] = {}
    for sub, base in parallel_map(probe, subs, workers=workers):
        if base:
            live[sub] = base
    return live


def _merge(result: ScanResult, sub_result: ScanResult) -> None:
    known_urls = {e.url for e in result.endpoints}
    for ep in sub_result.endpoints:
        if ep.url not in known_urls:
            result.endpoints.append(ep)
            known_urls.add(ep.url)

    existing = {f.dedup_key() for f in result.findings}
    for f in sub_result.findings:
        if f.dedup_key() not in existing:
            result.findings.append(f)
            existing.add(f.dedup_key())

    result.technologies = sorted(set(result.technologies) | set(sub_result.technologies))


def run(result: ScanResult, config: ScanConfig, ui, deadline: float | None = None) -> None:
    """Deepen the scan into live subdomains, merging results back in.

    ``deadline`` is a shared ``time.monotonic()`` cutoff for the whole run; once it
    passes, no new subdomain is started and the skipped count is recorded, so a
    100-subdomain target can never run for hours past ``--max-time``.
    """
    subs = [s for s in result.subdomains if s and s != result.target.host]
    if not subs:
        ui.info("No subdomains to deepen into.")
        return

    subs = subs[: config.max_subdomains]
    if len(result.subdomains) > config.max_subdomains:
        ui.warn(
            f"Deepening into first {config.max_subdomains} of "
            f"{len(result.subdomains)} subdomains (raise --max-subdomains to scan more)."
        )

    client = build_client(config)
    ui.info(f"Checking liveness of {len(subs)} subdomain(s)…")
    live = _live_subdomains(subs, client, config.concurrency)
    ui.good(f"Live subdomains: {len(live)}")

    # Web-layer only per subdomain, and deliberately light: no port scan, no
    # nuclei, no directory brute-force, and a shallow crawl — a broad sweep should
    # not spend the whole budget on one subdomain.
    sub_config = replace(
        config, run_nuclei=False, include_subdomains=False, dirbrute=False,
        crawl_depth=min(config.crawl_depth, 1),
        crawl_max_pages=min(config.crawl_max_pages, 40),
    )
    quiet = _QuietUI(ui)

    items = sorted(live.items())
    for index, (sub, base) in enumerate(items):
        if deadline is not None and time.monotonic() > deadline:
            skipped = len(items) - index
            ui.warn(f"Global time budget reached — skipping {skipped} remaining "
                    "subdomain(s) (raise --max-time or lower --max-subdomains).")
            result.errors.append(
                f"scan incomplete: time budget reached during subdomain deepening; "
                f"{skipped} subdomain(s) not scanned"
            )
            break
        ui.info(f"↳ {sub}")
        sub_result = ScanResult(
            target=Target(
                raw=sub, host=sub, base_url=base, ip=dnsx.resolve_ip(sub),
                scheme=base.split("://", 1)[0],
            )
        )
        try:
            active.run(sub_result, sub_config, quiet, web_only=True)
            engine.run(sub_result, sub_config, quiet, deadline=deadline)
        except Exception as exc:  # noqa: BLE001 - one bad subdomain never aborts
            result.errors.append(f"subdomain {sub}: {exc}")
            continue
        _merge(result, sub_result)
