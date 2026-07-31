"""Unit tests for the active crawler's extraction helpers."""

from __future__ import annotations

from strix.recon import crawler


def test_extract_links_absolute_and_scope_agnostic():
    html = """
      <a href="/about">about</a>
      <a href="products.php?id=1">p</a>
      <link href="https://cdn.other.com/style.css">
      <a href="mailto:a@b.com">mail</a>
      <a href="javascript:void(0)">x</a>
      <script src="/app.js"></script>
    """
    links = crawler.extract_links(html, "https://site.com/dir/page")
    assert "https://site.com/about" in links
    assert "https://site.com/dir/products.php?id=1" in links
    # css/js/mailto/javascript are skipped
    assert not any(l.endswith(".css") or l.endswith(".js") for l in links)
    assert not any("mailto" in l or "javascript" in l for l in links)


def test_extract_form_urls_builds_parametrized_get():
    html = """
      <form action="/search" method="get">
        <input name="q"><input name="cat"><textarea name="note"></textarea>
      </form>
      <form action="login.php" method="post">
        <input name="user"><input name="pass">
      </form>
    """
    urls = crawler.extract_form_urls(html, "https://site.com/page")
    search = next(u for u in urls if "/search" in u)
    assert "q=1" in search and "cat=1" in search and "note=1" in search
    # POST form params are still recorded as candidate injection points
    assert any("login.php" in u and "user=1" in u for u in urls)


def test_extract_form_without_inputs_ignored():
    assert crawler.extract_form_urls("<form action='/x'></form>", "https://s.com") == []
