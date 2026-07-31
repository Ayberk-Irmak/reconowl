# Contributing to Strix

Thanks for your interest in improving Strix.

## Development setup

```bash
git clone <your-fork-url> strix && cd strix
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
pytest
```

## Adding a vulnerability check

Checks live in `strix/scan/` and share one signature:

```python
def check(result, config, client, ui) -> list[Finding]:
    ...
```

Guidelines:

- **Pure, testable core.** Put detection logic in small pure functions (e.g.
  `detect(...)`, `analyze(...)`) and unit-test them without network.
- **Low false positives.** Confirm findings by a distinctive, computed, or
  out-of-band signal — never by mere reflection of the payload.
- **Respect scope.** Use `strix.utils.net.in_scope(...)` so active payloads only
  reach the target and its sibling subdomains.
- **Be responsible.** If a check mutates server state, restore it and say so in
  the finding description.
- **Register** the check in `strix/scan/engine.py` (`_NATIVE_CHECKS`) and add a
  CVSS vector in `strix/scoring.py`.
- **Add tests** in `tests/` covering the pure logic and a `check()` path with a
  fake client.

## Before opening a PR

```bash
python -m compileall -q strix
pytest
```

Keep modules small and single-responsibility; match the surrounding style.
