"""HTML report — a self-contained, styled page rendered with Jinja2."""

from __future__ import annotations

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..models import ScanResult, Severity

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def render(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")

    findings = []
    for f in result.sorted_findings():
        d = f.to_dict()
        d["severity_l"] = f.severity.label.lower()
        findings.append(d)

    counts = result.severity_counts()
    return template.render(
        version=__version__,
        target=result.target.to_dict(),
        started_at=result.started_at,
        finished_at=result.finished_at,
        tools_used=result.tools_used,
        severities=[s.label for s in reversed(Severity)],
        counts=counts,
        max_cvss=result.max_cvss(),
        findings=findings,
        ports=[p.to_dict() for p in result.ports],
        endpoints=[e.to_dict() for e in result.endpoints],
        tls=result.tls,
        subdomains=result.subdomains,
        dns_records=result.dns_records,
        urls=result.urls,
        errors=result.errors,
    )


def write(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
