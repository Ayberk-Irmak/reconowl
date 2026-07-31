"""Report rendering from a ScanResult: HTML, JSON, and Markdown."""

from __future__ import annotations

import os

from ..models import ScanResult
from . import html as html_report
from . import json_report, markdown, sarif


def write(result: ScanResult, output_dir: str, formats: list[str]) -> dict[str, str]:
    """Render the requested formats into ``output_dir``; return {fmt: path}."""
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.join(output_dir, "report")
    written: dict[str, str] = {}

    if "json" in formats:
        path = base + ".json"
        json_report.write(result, path)
        written["json"] = path
    if "md" in formats:
        path = base + ".md"
        markdown.write(result, path)
        written["md"] = path
    if "html" in formats:
        path = base + ".html"
        html_report.write(result, path)
        written["html"] = path
    if "sarif" in formats:
        path = base + ".sarif"
        sarif.write(result, path)
        written["sarif"] = path
    return written
