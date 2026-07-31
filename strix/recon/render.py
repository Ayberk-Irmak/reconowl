"""Headless JS rendering for SPA-heavy targets.

Static crawling misses single-page apps (React/Vue/Angular/Next/…) whose links,
forms, and API calls are produced client-side. When Playwright + a browser are
available, we render seed pages headlessly, then reuse the normal extractors on
the *rendered* DOM and additionally harvest the XHR/fetch endpoints the app
calls — often the real API attack surface.

Everything degrades gracefully: if no browser is installed the crawler simply
falls back to static HTML + JS-bundle endpoint extraction.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
from dataclasses import dataclass, field

_PROBE = (
    "from playwright.sync_api import sync_playwright\n"
    "with sync_playwright() as p:\n"
    "    b = p.chromium.launch(headless=True); b.close()\n"
    "print('OK')\n"
)

# Mount points that strongly indicate a client-rendered SPA shell.
_SPA_MOUNTS = (
    'id="root"', "id='root'", 'id="app"', "id='app'", 'id="__next"', 'id="__nuxt"',
    "ng-app", "data-reactroot", "data-server-rendered", "v-app", "data-v-app",
)


@dataclass
class RenderedPage:
    url: str
    html: str = ""
    xhr: list[str] = field(default_factory=list)
    ok: bool = False


def looks_like_spa(html: str, inscope_links: int) -> bool:
    """Heuristic: a page worth rendering (few server-side links + SPA markers)."""
    low = (html or "").lower()
    has_mount = any(m in low for m in _SPA_MOUNTS)
    has_bundle = "<script" in low and (".js" in low or "src=" in low)
    if inscope_links >= 5:
        return False  # a normal multi-page site — static crawl is enough
    return has_mount or (has_bundle and inscope_links < 2)


_AVAILABLE: bool | None = None


def available() -> bool:
    """True if Playwright and a working Chromium are installed (cached, quiet).

    Probes in a subprocess so a broken/half-installed Playwright can't leave
    dangling asyncio tasks or stderr noise in the scanner process.
    """
    global _AVAILABLE
    if _AVAILABLE is not None:
        return _AVAILABLE
    try:
        import importlib.util
        if importlib.util.find_spec("playwright") is None:
            _AVAILABLE = False
            return _AVAILABLE
        proc = subprocess.run(
            [sys.executable, "-c", _PROBE],
            capture_output=True, text=True, timeout=40,
        )
        _AVAILABLE = proc.returncode == 0 and "OK" in proc.stdout
    except Exception:  # noqa: BLE001 - timeout / no browser / launch failure
        _AVAILABLE = False
    return _AVAILABLE


def render_pages(urls: list[str], config, ui=None) -> list[RenderedPage]:
    """Render each URL headlessly, returning rendered DOM + captured XHR/fetch URLs."""
    if not urls or not available():
        return []
    from playwright.sync_api import sync_playwright

    out: list[RenderedPage] = []
    timeout_ms = int(max(getattr(config, "timeout", 12.0), 5.0) * 1000)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=getattr(config, "user_agent", "strix/0.1"),
                ignore_https_errors=True,
                extra_http_headers=config.build_headers(),
            )
            for url in urls:
                page = context.new_page()
                xhr: list[str] = []
                page.on(
                    "request",
                    lambda req: xhr.append(req.url)
                    if req.resource_type in ("xhr", "fetch") else None,
                )
                try:
                    page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    with contextlib.suppress(Exception):
                        page.wait_for_timeout(500)  # let late XHRs settle
                    out.append(RenderedPage(url=url, html=page.content(), xhr=list(xhr), ok=True))
                except Exception:  # noqa: BLE001 - navigation/timeout on one page
                    out.append(RenderedPage(url=url, ok=False))
                finally:
                    with contextlib.suppress(Exception):
                        page.close()
            browser.close()
    except Exception:  # noqa: BLE001 - browser died mid-run; return what we have
        return out
    return out
