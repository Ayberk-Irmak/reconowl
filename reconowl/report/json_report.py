"""JSON report — the full, machine-readable scan result."""

from __future__ import annotations

import json

from ..models import ScanResult


def render(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def write(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
