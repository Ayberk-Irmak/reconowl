"""A tiny bounded-parallelism helper over a thread pool."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(
    func: Callable[[T], R],
    items: Iterable[T],
    *,
    workers: int = 20,
) -> Iterator[tuple[T, R]]:
    """Apply ``func`` to each item concurrently, yielding ``(item, result)``.

    Exceptions in ``func`` are swallowed per-item (result yielded as ``None``) so
    one bad host never aborts a whole phase. Order is completion order.
    """
    items = list(items)
    if not items:
        return
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        futures = {pool.submit(func, item): item for item in items}
        for future in as_completed(futures):
            item = futures[future]
            try:
                yield item, future.result()
            except Exception:  # noqa: BLE001 - isolate per-item failures
                yield item, None  # type: ignore[misc]
