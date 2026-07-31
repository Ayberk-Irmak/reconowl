"""Unit tests for external-tool output parsers (no processes spawned)."""

from __future__ import annotations

from strix.external import httpx_tool, nmap
from strix.models import Severity
from strix.scan import nuclei_scan

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_parse_only_open_ports():
    ports = nmap.parse_xml(_NMAP_XML)
    nums = [p.number for p in ports]
    assert nums == [22, 443]  # closed 8080 dropped, sorted
    assert ports[0].service == "ssh" and ports[0].product == "OpenSSH"
    assert ports[1].version == "1.24.0"


def test_nmap_parse_garbage():
    assert nmap.parse_xml("not xml") == []


def test_httpx_parse_jsonl():
    text = (
        '{"url":"https://a.com","status_code":200,"title":"Home",'
        '"webserver":"nginx","tech":["PHP","jQuery"],"content_type":"text/html"}\n'
        "garbage line\n"
        '{"url":"https://b.com","status_code":403}'
    )
    eps = httpx_tool.parse_jsonl(text)
    assert len(eps) == 2
    assert eps[0].url == "https://a.com" and eps[0].status == 200
    assert "PHP" in eps[0].technologies
    assert eps[1].status == 403


def test_nuclei_parse():
    text = (
        '{"template-id":"tech-detect","matched-at":"https://a.com",'
        '"info":{"name":"Nginx","severity":"info","tags":["tech"]}}\n'
        '{"template-id":"CVE-2021-1234","matched-at":"https://a.com/x",'
        '"info":{"name":"RCE","severity":"critical","reference":["https://x"],'
        '"classification":{"cve-id":["CVE-2021-1234"]}}}'
    )
    findings = nuclei_scan._parse(text, "a.com")
    assert len(findings) == 2
    assert findings[0].severity is Severity.INFO
    crit = findings[1]
    assert crit.severity is Severity.CRITICAL
    assert crit.references == ["https://x"]
    assert crit.extra["cve"] == ["CVE-2021-1234"]
