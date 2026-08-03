"""Active crawler — discovers in-scope URLs (and form parameters) to test.

Passive sources (Wayback/sitemap) are often empty for a site, leaving the
injection checks with nothing to probe. This crawler fetches pages breadth-first,
extracts links and — importantly — builds parametrized URLs from HTML forms, so
SQLi/XSS/LFI/etc. have real inputs to hit. Optionally augmented by ``katana``.
"""

from __future__ import annotations

import re
import urllib.parse

from ..config import ScanConfig
from ..external import katana
from ..models import Form, ScanResult
from ..utils.concurrency import parallel_map
from ..utils.net import build_client, in_scope
from . import render

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#>\s]+)""", re.I)
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"'>\s]+)""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"'>\s]+)""", re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?\s*(get|post)""", re.I)
_INPUT_NAME_RE = re.compile(r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"'>\s]+)""", re.I)

_SKIP_EXT = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".mp4", ".webp", ".map",
)

# Never follow these — they would destroy an authenticated session mid-crawl.
_LOGOUT_RE = re.compile(r"(log[\-_]?out|sign[\-_]?out|log[\-_]?off|/logout|/signout)", re.I)


def _is_logout(url: str) -> bool:
    return bool(_LOGOUT_RE.search(urllib.parse.urlsplit(url).path))


def extract_links(html: str, page_url: str) -> list[str]:
    """Absolute http(s) links from a page's href/src/action attributes."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in _LINK_RE.findall(html or ""):
        raw = raw.strip()
        if not raw or raw.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urllib.parse.urljoin(page_url, raw)
        absolute, _frag = urllib.parse.urldefrag(absolute)
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            continue
        if parts.path.lower().endswith(_SKIP_EXT):
            continue
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out


def extract_script_srcs(html: str, page_url: str) -> list[str]:
    """Absolute URLs of <script src> JavaScript files on a page."""
    out: list[str] = []
    for raw in _SCRIPT_SRC_RE.findall(html or ""):
        absolute = urllib.parse.urljoin(page_url, raw.strip())
        if urllib.parse.urlsplit(absolute).scheme in ("http", "https"):
            out.append(absolute.split("#")[0])
    return out


def extract_forms(html: str, page_url: str) -> list[Form]:
    """Extract structured forms (action URL, method, param names)."""
    out: list[Form] = []
    for m in _FORM_RE.finditer(html or ""):
        tag = m.group(0)
        method_m = _METHOD_RE.search(tag)
        method = (method_m.group(1).upper() if method_m else "GET")
        action_m = _ACTION_RE.search(tag)
        action = action_m.group(1) if action_m else ""
        target = urllib.parse.urljoin(page_url, action) if action else page_url
        target, _frag = urllib.parse.urldefrag(target)
        names = list(dict.fromkeys(_INPUT_NAME_RE.findall(tag)))
        if names and urllib.parse.urlsplit(target).scheme in ("http", "https"):
            out.append(Form(url=target, method=method, params=names))
    return out


def extract_form_urls(html: str, page_url: str) -> list[str]:
    """Build parametrized GET URLs from forms so params can be tested."""
    out: list[str] = []
    for form in extract_forms(html, page_url):
        query = urllib.parse.urlencode([(n, "1") for n in form.params])
        parts = urllib.parse.urlsplit(form.url)
        out.append(urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
    return out


def _katana_urls(base: str, config: ScanConfig) -> list[str]:
    if not (config.use_external and katana.available()):
        return []
    return katana.crawl(base, depth=config.crawl_depth, headers=config.build_headers())


def run(result: ScanResult, config: ScanConfig, ui) -> None:
    """Crawl the target, adding discovered URLs to ``result.urls``."""
    if not config.crawl:
        return
    base = result.target.base_url
    if not base:
        return

    host = result.target.host
    client = build_client(config, timeout=min(config.timeout, 8.0))

    known = set(result.urls)
    before = len(known)
    # Let the crawler add live-discovered URLs on top of passive ones, so a full
    # Wayback dump doesn't starve crawling of new (often more valuable) URLs.
    url_cap = before + config.crawl_max_pages
    form_keys = {(f.url, f.method, tuple(f.params)) for f in result.forms}

    def add(url: str) -> None:
        if in_scope(url, host) and not _is_logout(url):
            # Mark as crawler-discovered even if it was already harvested passively,
            # so the injection checks prioritise live-seen URLs over archive URLs.
            result.crawled.add(url)
        if (url not in known and in_scope(url, host) and not _is_logout(url)
                and len(result.urls) < url_cap):
            known.add(url)
            result.urls.append(url)

    def add_form(form: Form) -> None:
        key = (form.url, form.method, tuple(form.params))
        if key not in form_keys and in_scope(form.url, host):
            form_keys.add(key)
            result.forms.append(form)

    # Optional deep crawl via katana (fast, JS-aware) as a seed.
    for url in _katana_urls(base, config):
        add(url)

    ui.info(f"Crawling {host} (depth {config.crawl_depth}, up to {config.crawl_max_pages} pages)…")
    visited: set[str] = set()
    frontier = [base] + [e.url for e in result.endpoints]
    pages = 0

    def fetch(url: str):
        resp = client.get(url)
        if not resp.ok or "html" not in resp.header("content-type").lower():
            return None
        return resp

    for _depth in range(max(0, config.crawl_depth) + 1):
        if pages >= config.crawl_max_pages:
            break
        batch = [u for u in dict.fromkeys(frontier) if u not in visited][
            : config.crawl_max_pages - pages
        ]
        if not batch:
            break
        next_frontier: list[str] = []
        for url, resp in parallel_map(fetch, batch, workers=config.concurrency):
            visited.add(url)
            if resp is None:
                continue
            pages += 1
            for link in extract_links(resp.text, url):
                add(link)
                if in_scope(link, host) and link not in visited and not _is_logout(link):
                    next_frontier.append(link)
            for js in extract_script_srcs(resp.text, url):
                if in_scope(js, host) and js not in result.js_files:
                    result.js_files.append(js)
            for form in extract_forms(resp.text, url):
                add_form(form)
                if form.method == "GET":  # GET forms are also testable as URL query
                    query = urllib.parse.urlencode([(n, "1") for n in form.params])
                    parts = urllib.parse.urlsplit(form.url)
                    add(urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
        frontier = next_frontier

    static_added = len(result.urls) - before
    _render_pass(result, config, ui, client, base, host, static_added, add, add_form)

    added = len(result.urls) - before
    forms = len(result.forms)
    ui.good(f"Crawl: {pages} page(s), {added} new URL(s), {forms} form(s) (total {len(result.urls)})")


def _render_pass(result, config, ui, client, base, host, static_added, add, add_form):
    """Optionally render seed pages headlessly to recover SPA links/forms/APIs."""
    mode = getattr(config, "render_mode", "auto")
    if mode == "off" or not base:
        return

    render_urls: list[str] = []
    if mode == "on":
        render_urls = [base] + [u for u in result.urls if in_scope(u, host)]
    elif static_added < 5:  # auto: only bother when static crawl found little
        probe = client.get(base)
        if probe.ok and "html" in probe.header("content-type").lower():
            links = [ln for ln in extract_links(probe.text, base) if in_scope(ln, host)]
            if render.looks_like_spa(probe.text, len(links)):
                render_urls = [base]

    if not render_urls or not render.available():
        if render_urls and not render.available():
            ui.warn("JS-render: target looks like a SPA but no headless browser is "
                    "available — install Playwright (`playwright install chromium`) for "
                    "full coverage. Falling back to static + JS-endpoint extraction.")
        return

    render_urls = list(dict.fromkeys(render_urls))[: getattr(config, "render_max_pages", 5)]
    ui.info(f"JS-render: rendering {len(render_urls)} page(s) with a headless browser…")
    r_links = r_forms = r_xhr = 0
    for rp in render.render_pages(render_urls, config, ui):
        if not rp.ok:
            continue
        before_urls = len(result.urls)
        for link in extract_links(rp.html, rp.url):
            add(link)
        for js in extract_script_srcs(rp.html, rp.url):
            if in_scope(js, host) and js not in result.js_files:
                result.js_files.append(js)
        for form in extract_forms(rp.html, rp.url):
            add_form(form)
            r_forms += 1
            if form.method == "GET":
                query = urllib.parse.urlencode([(n, "1") for n in form.params])
                parts = urllib.parse.urlsplit(form.url)
                add(urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")))
        for endpoint in rp.xhr:  # captured API calls — real SPA attack surface
            if in_scope(endpoint, host):
                add(endpoint)
                r_xhr += 1
        r_links += len(result.urls) - before_urls
    ui.good(f"JS-render: +{r_links} URL(s), +{r_forms} form(s), {r_xhr} XHR/fetch endpoint(s)")
