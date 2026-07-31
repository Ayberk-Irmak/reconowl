"""nmap orchestration: run a connect-scan and parse the XML output."""

from __future__ import annotations

from xml.etree import ElementTree

from ..models import Port
from ..utils.tools import find_tool, run


def available() -> bool:
    return find_tool("nmap") is not None


def scan(host: str, port_spec: str, *, extra: list[str] | None = None, timeout: float = 600.0) -> tuple[list[Port], str]:
    """Run nmap against ``host`` and return ``(ports, raw_xml)``.

    Uses a TCP connect scan (``-sT``) so it does not require root, skips host
    discovery (``-Pn``) since targets often drop pings, and enables service/
    version detection (``-sV``).
    """
    args = ["-sT", "-Pn", "-sV", "-T4", "--host-timeout", "300s"]
    args += port_spec.split()
    if extra:
        args += extra
    args += ["-oX", "-", host]

    code, out, err = run("nmap", args, timeout=timeout)
    if not out.strip():
        return [], err or out
    return parse_xml(out), out


def parse_xml(xml_text: str) -> list[Port]:
    """Parse nmap ``-oX`` output into :class:`Port` objects."""
    ports: list[Port] = []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return ports

    for host_el in root.findall("host"):
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            svc = port_el.find("service")
            ports.append(
                Port(
                    number=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state,
                    service=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                )
            )
    return sorted(ports, key=lambda p: p.number)
