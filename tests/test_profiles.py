"""Tests for --profile presets and their override semantics."""

from __future__ import annotations

from reconowl.cli import build_config, build_parser


def _cfg(*argv):
    return build_config(build_parser().parse_args(["example.com", *argv]))


def test_default_profile_is_standard():
    c = _cfg()
    assert c.intensity == "normal"
    assert c.include_subdomains is False
    assert c.max_scan_seconds == 900.0
    assert c.dirbrute is True


def test_quick_profile():
    c = _cfg("--profile", "quick")
    assert c.intensity == "light"
    assert c.max_scan_seconds == 300.0
    assert c.dirbrute is False
    assert c.render_mode == "off"


def test_deep_profile_enables_subdomains_and_bigger_budget():
    c = _cfg("--profile", "deep")
    assert c.include_subdomains is True
    assert c.intensity == "aggressive"
    assert c.max_scan_seconds == 2400.0


def test_stealth_profile_sets_polite_pacing():
    c = _cfg("--profile", "stealth")
    assert c.rate_limit == 2.0 and c.jitter == 0.4 and c.concurrency == 3
    assert c.dirbrute is False


def test_explicit_flag_overrides_profile():
    # deep enables subdomains, but --no-subdomains must win; --max-time overrides too.
    c = _cfg("--profile", "deep", "--no-subdomains", "--max-time", "120")
    assert c.include_subdomains is False
    assert c.max_scan_seconds == 120.0
    # intensity still comes from the profile when not overridden
    assert c.intensity == "aggressive"


def test_stealth_flag_layers_pacing_on_any_profile():
    # --stealth applies polite pacing without changing which checks run.
    c = _cfg("--profile", "deep", "--stealth")
    assert c.concurrency == 3 and c.rate_limit == 2.0 and c.jitter == 0.4
    assert c.include_subdomains is True  # deep coverage kept


def test_intensity_flag_overrides_profile_intensity():
    c = _cfg("--profile", "quick", "-i", "aggressive")
    assert c.intensity == "aggressive"
