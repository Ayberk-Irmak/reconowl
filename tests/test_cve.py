"""Unit tests for version→CVE matching."""

from __future__ import annotations

from strix.models import Port, ScanResult, Severity, Target, WebEndpoint
from strix.scan import cve


def test_parse_version_tolerant():
    assert cve.parse_version("2.4.7 (Ubuntu)") == (2, 4, 7)
    assert cve.parse_version("6.6.1p1") == (6, 6, 1)
    assert cve.parse_version("nope") == ()


def test_version_matches_ranges():
    assert cve.version_matches("2.4.7", "<2.4.30")
    assert not cve.version_matches("2.4.49", "<2.4.30")
    assert cve.version_matches("2.4.49", ">=2.4.49,<2.4.51")
    assert not cve.version_matches("2.4.51", ">=2.4.49,<2.4.51")
    assert cve.version_matches("2.3.4", "==2.3.4")
    assert not cve.version_matches("2.3.5", "==2.3.4")


def test_extract_software_from_ports_and_server():
    r = ScanResult(target=Target(raw="t", host="t"))
    r.ports = [Port(number=22, service="ssh", product="OpenSSH", version="6.6.1p1"),
               Port(number=80, service="http", product="Apache httpd", version="2.4.7")]
    r.endpoints = [WebEndpoint(url="https://t", server="Apache/2.4.7 (Ubuntu)",
                               technologies=["PHP:5.2.4", "jQuery:3.3.1"])]
    sw = cve.extract_software(r)
    names = {n.lower() for n, _v, _s in sw}
    assert any("openssh" in n for n in names)
    assert any("apache" in n for n in names)
    assert any("php" in n for n in names)


def test_match_cves_real_hits():
    db = cve.load_db()
    assert db, "cve_db.json should load"
    # Apache 2.4.7 -> older CVEs; OpenSSH 6.6.1 -> username enum; vsftpd 2.3.4 -> backdoor
    hits = cve.match([
        ("Apache httpd", "2.4.7", "port 80"),
        ("OpenSSH", "6.6.1p1", "port 22"),
        ("vsftpd", "2.3.4", "port 21"),
        ("PHP", "5.2.4", "tech"),
    ], db)
    ids = {h["cve"] for h in hits}
    assert "CVE-2018-15473" in ids       # OpenSSH < 7.7
    assert "CVE-2011-2523" in ids        # vsftpd 2.3.4 backdoor
    assert "CVE-2012-1823" in ids        # PHP < 5.4.2
    assert any(h["product"] == "apache httpd" for h in hits)


def test_check_uses_cve_cvss_and_reference():
    r = ScanResult(target=Target(raw="t", host="t"))
    r.ports = [Port(number=21, service="ftp", product="vsftpd", version="2.3.4")]

    class Cfg:
        cve_lookup = True

    findings = cve.check(r, Cfg(), None, None)
    f = next(x for x in findings if "CVE-2011-2523" in x.title)
    assert f.category == "cve"
    assert f.cvss_score == 9.8               # from DB, not recomputed
    assert f.severity is Severity.CRITICAL
    assert any("nvd.nist.gov" in ref for ref in f.references)
