"""Optional katana crawler orchestration (used to seed the native crawler)."""

from __future__ import annotations

from ..utils.tools import find_tool, run


def available() -> bool:
    return find_tool("katana") is not None


def crawl(base_url: str, *, depth: int = 2, headers: dict[str, str] | None = None,
          timeout: float = 180.0) -> list[str]:
    """Run katana and return discovered URLs (empty on failure)."""
    args = ["-u", base_url, "-depth", str(max(1, depth)), "-silent", "-nc"]
    for key, value in (headers or {}).items():
        args += ["-H", f"{key}: {value}"]
    code, out, _err = run("katana", args, timeout=timeout)
    urls: list[str] = []
    seen: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("http") and line not in seen:
            seen.add(line)
            urls.append(line)
    return urls
