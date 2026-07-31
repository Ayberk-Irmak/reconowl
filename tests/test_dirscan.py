"""Unit tests for the directory brute-force check (pure logic, no network)."""

from __future__ import annotations

from reconowl.models import Severity
from reconowl.scan import dirscan


def test_load_wordlist_skips_comments_and_dupes(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("# comment\nadmin\n\nadmin\nlogin\n  \nconfig\n")
    words = dirscan.load_wordlist(str(wl))
    assert words == ["admin", "login", "config"]


def test_builtin_wordlist_loads():
    assert len(dirscan.load_wordlist()) > 100


def test_baseline_soft404_200_filtered_by_length():
    bl = dirscan._Baseline(statuses={200}, lengths=[500])
    # A 200 with near-identical length is the site's soft-404.
    assert bl.looks_like_not_found(200, 520, "") is True
    # A 200 with very different length is a real page.
    assert bl.looks_like_not_found(200, 2000, "") is False


def test_baseline_redirect_match():
    bl = dirscan._Baseline(statuses={302}, locations={"/login"})
    assert bl.looks_like_not_found(302, 0, "https://a.com/login") is True
    assert bl.looks_like_not_found(302, 0, "https://a.com/somewhere-else") is False


def test_baseline_status_not_seen_is_interesting():
    bl = dirscan._Baseline(statuses={404}, lengths=[100])
    assert bl.looks_like_not_found(403, 100, "") is False  # 403 never seen -> interesting


def test_classify_directory_listing_is_medium():
    f = dirscan._classify("uploads", "http://a/uploads", 200, "<h1>Index of /uploads</h1>")
    assert f is not None and f.severity is Severity.MEDIUM and f.category == "dir-listing"


def test_classify_protected_is_info():
    f = dirscan._classify("secret", "http://a/secret", 403, "Forbidden")
    assert f is not None and f.category == "dir-protected" and f.severity is Severity.INFO


def test_classify_sensitive_200_is_low():
    f = dirscan._classify("backup", "http://a/backup", 200, "files")
    assert f is not None and f.severity is Severity.LOW and f.category == "dir-found-sensitive"


def test_classify_generic_200_is_info():
    f = dirscan._classify("home", "http://a/home", 200, "welcome")
    # Benign accessible paths score INFO/0.0 (category not caught by the "dir-" vector).
    assert f is not None and f.severity is Severity.INFO and f.category == "path-accessible"
