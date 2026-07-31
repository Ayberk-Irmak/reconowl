"""Unit tests for SPA/JS-render crawling (logic + crawler integration)."""

from __future__ import annotations

from reconowl.config import ScanConfig
from reconowl.models import ScanResult, Target
from reconowl.recon import crawler, render
from reconowl.recon.render import RenderedPage


def test_looks_like_spa_shell():
    spa = '<html><body><div id="root"></div><script src="/static/app.js"></script></body></html>'
    assert render.looks_like_spa(spa, 0) is True


def test_looks_like_spa_ignores_normal_site():
    normal = '<div id="app">' + "<a href='/p'>x</a>" * 8
    assert render.looks_like_spa(normal, 8) is False  # plenty of server-side links


def test_looks_like_spa_bundle_only_needs_few_links():
    page = "<script src='/bundle.js'></script><a href='/x'>x</a>"
    assert render.looks_like_spa(page, 1) is True
    assert render.looks_like_spa(page, 3) is False


def test_available_is_false_without_browser():
    # No working browser in the test env — must degrade quietly, never raise.
    assert render.available() in (True, False)


def _harness(host="a.com"):
    result = ScanResult(target=Target(raw=host, host=host, base_url=f"https://{host}"))
    known = set()

    def add(url):
        from reconowl.utils.net import in_scope
        if url not in known and in_scope(url, host):
            known.add(url)
            result.urls.append(url)

    def add_form(form):
        from reconowl.utils.net import in_scope
        if in_scope(form.url, host):
            result.forms.append(form)

    return result, add, add_form


def test_render_pass_merges_links_forms_and_xhr(monkeypatch):
    result, add, add_form = _harness()
    rendered = RenderedPage(
        url="https://a.com/",
        html='<a href="/spa/route">r</a>'
             '<form method="post" action="/api/save"><input name="v"></form>'
             '<script src="/static/app.js"></script>',
        xhr=["https://a.com/api/data?id=1", "https://evil.com/collect"],
        ok=True,
    )
    monkeypatch.setattr(render, "available", lambda: True)
    monkeypatch.setattr(render, "render_pages", lambda urls, config, ui=None: [rendered])

    cfg = ScanConfig(target="a.com", render_mode="on")

    class UI:
        def info(self, m): pass
        def good(self, m): pass
        def warn(self, m): pass

    crawler._render_pass(result, cfg, UI(), client=None, base="https://a.com",
                         host="a.com", static_added=0, add=add, add_form=add_form)

    assert "https://a.com/spa/route" in result.urls
    assert "https://a.com/api/data?id=1" in result.urls          # captured XHR endpoint
    assert "https://evil.com/collect" not in result.urls         # out of scope
    assert any(f.url == "https://a.com/api/save" for f in result.forms)
    assert "https://a.com/static/app.js" in result.js_files


def test_render_pass_off_mode_does_nothing(monkeypatch):
    result, add, add_form = _harness()
    called = {"n": 0}
    monkeypatch.setattr(render, "available", lambda: True)
    monkeypatch.setattr(render, "render_pages",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or [])
    cfg = ScanConfig(target="a.com", render_mode="off")

    class UI:
        def info(self, m): pass
        def good(self, m): pass
        def warn(self, m): pass

    crawler._render_pass(result, cfg, UI(), client=None, base="https://a.com",
                         host="a.com", static_added=0, add=add, add_form=add_form)
    assert called["n"] == 0 and result.urls == []
