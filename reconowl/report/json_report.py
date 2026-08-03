"""JSON report — the full, machine-readable scan result."""

from __future__ import annotations

import json

from ..models import ScanResult
from .summary import build_summary


def render(result: ScanResult) -> str:
    data = result.to_dict()
    # Executive summary + coverage assessment up top for consumers/automation.
    data = {"summary": build_summary(result), **data}
    return json.dumps(data, indent=2, ensure_ascii=False)


def write(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
