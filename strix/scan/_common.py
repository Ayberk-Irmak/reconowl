"""Shared helpers for the injection-family checks."""

from __future__ import annotations

from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient


def fetch_baselines(
    client: HttpClient, candidates: list[tuple[str, str]], workers: int
) -> dict[str, str]:
    """Fetch each unique candidate URL's baseline body once, concurrently."""
    unique_urls = list({url for url, _ in candidates})
    cache: dict[str, str] = {}
    for url, resp in parallel_map(client.get, unique_urls, workers=workers):
        cache[url] = resp.text if (resp is not None and resp.ok) else ""
    return cache


def point_baselines(client: HttpClient, points: list, workers: int) -> dict:
    """Fetch one baseline body per unique injection-point request, concurrently."""
    from . import injpoints

    reps: dict = {}
    for p in points:
        reps.setdefault(injpoints.baseline_key(p), p)
    cache: dict = {}
    for point, resp in parallel_map(
        lambda pt: injpoints.baseline(client, pt), list(reps.values()), workers=workers
    ):
        cache[injpoints.baseline_key(point)] = resp.text if (resp is not None and resp.ok) else ""
    return cache
