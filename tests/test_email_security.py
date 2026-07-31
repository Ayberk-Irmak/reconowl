"""Unit tests for the SPF/DMARC/DKIM email-security check."""

from __future__ import annotations

from reconowl.scan import email_security as es
from reconowl.scan.engine import _WEB_INDEPENDENT


def test_spf_all_qualifier():
    assert es._spf_all_qualifier("v=spf1 include:x.com -all") == "-"
    assert es._spf_all_qualifier("v=spf1 ~all") == "~"
    assert es._spf_all_qualifier("v=spf1 +all") == "+"
    assert es._spf_all_qualifier("v=spf1 ?all") == "?"
    assert es._spf_all_qualifier("v=spf1 include:x.com") == ""


def test_spf_missing():
    f = es._eval_spf("ex.com", "ex.com", ["some=other"])
    assert len(f) == 1 and f[0].category == "spf-missing"


def test_spf_hardfail_ok():
    assert es._eval_spf("ex.com", "ex.com", ["v=spf1 include:a -all"]) == []


def test_spf_permissive_is_high():
    f = es._eval_spf("ex.com", "ex.com", ["v=spf1 +all"])
    assert f[0].category == "spf-permissive" and f[0].severity.name == "HIGH"


def test_spf_weak_neutral():
    f = es._eval_spf("ex.com", "ex.com", ["v=spf1 ?all"])
    assert f[0].category == "spf-weak" and f[0].severity.name == "LOW"


def test_spf_multiple():
    f = es._eval_spf("ex.com", "ex.com", ["v=spf1 -all", "v=spf1 include:y -all"])
    assert f[0].category == "spf-multiple"


def test_dmarc_missing():
    f = es._eval_dmarc("ex.com", "ex.com", [])
    assert len(f) == 1 and f[0].category == "dmarc-missing"


def test_dmarc_reject_ok():
    assert es._eval_dmarc("ex.com", "ex.com", ["v=DMARC1; p=reject; rua=mailto:x"]) == []


def test_dmarc_none_is_weak():
    f = es._eval_dmarc("ex.com", "ex.com", ["v=DMARC1; p=none"])
    assert f[0].category == "dmarc-weak"


def test_dmarc_pct_partial():
    f = es._eval_dmarc("ex.com", "ex.com", ["v=DMARC1; p=reject; pct=50"])
    assert any("pct" in x.title for x in f)


def test_email_check_registered_web_independent():
    assert "Email security (SPF/DMARC/DKIM)" in _WEB_INDEPENDENT
