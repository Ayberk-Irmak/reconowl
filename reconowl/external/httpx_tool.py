"""ProjectDiscovery httpx orchestration: probe URLs, parse JSONL output.

Note: this drives the Go ``httpx`` binary (on PATH in Kali), not the Python
``httpx`` library.
"""

from __future__ import annotations

import json

from ..models import WebEndpoint
from ..utils.tools import find_tool, header_flags, run


def available() -> bool:
    return find_tool("httpx") is not None


def probe(urls: list[str], *, timeout: float = 180.0, headers: dict[str, str] | None = None) -> list[WebEndpoint]:
    """Probe ``urls`` with httpx and return structured endpoints."""
    if not urls:
        return []
    args = [
        "-silent", "-json", "-no-color",
        "-title", "-status-code", "-tech-detect",
        "-web-server", "-content-length", "-content-type",
        "-follow-redirects", "-timeout", "10",
        *header_flags(headers or {}),
    ]
    code, out, err = run("httpx", args, timeout=timeout, input_text="\n".join(urls))
    return parse_jsonl(out)


def parse_jsonl(text: str) -> list[WebEndpoint]:
    """Parse httpx ``-json`` output (one JSON object per line)."""
    endpoints: list[WebEndpoint] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        endpoints.append(
            WebEndpoint(
                url=obj.get("url", obj.get("input", "")),
                status=obj.get("status_code"),
                title=obj.get("title", ""),
                server=obj.get("webserver", ""),
                content_type=obj.get("content_type", ""),
                content_length=obj.get("content_length"),
                technologies=obj.get("tech", []) or [],
                redirect=obj.get("final_url", "") if obj.get("final_url") != obj.get("url") else "",
            )
        )
    return endpoints
