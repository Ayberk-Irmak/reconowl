"""Native check: OS command injection.

Two detection strategies:

- **Output-based** — inject shell separators plus ``id`` / an arithmetic
  expansion; a hit is the ``uid=…gid=…`` pattern or the *computed* product in the
  response (neither of which is in the payload, so reflection can't fake it).
- **Time-based (blind)** — inject ``sleep N``; a hit is the response taking ~N
  seconds longer than a fast baseline. Catches injection with no reflected output.

Both are strong RCE indicators, so confirmed hits are Critical.
"""

from __future__ import annotations

import re
import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof, in_scope
from . import injpoints
from ._common import point_baselines

_SOURCE = "native:cmdi"

_MARK = "CMDi"
_A, _B = 1009, 1013
_PRODUCT = str(_A * _B)  # 1022117
_ARITH = f"$(({_A}*{_B}))"
_ID_RE = re.compile(r"uid=\d+\([\w-]*\)\s+gid=\d+")

_SEPS = (";", "|", "||", "&&", "&", "\n")
_SLEEP = 5

_OUT_PAYLOADS = tuple(
    p
    for sep in _SEPS
    for p in (f"{sep}id", f"{sep}echo {_MARK}{_ARITH}{_MARK}", f"1{sep}id")
) + ("`id`", "$(id)", f"`echo {_MARK}{_ARITH}{_MARK}`", f"$(echo {_MARK}{_ARITH}{_MARK})")

_TIME_PAYLOADS = (
    f";sleep {_SLEEP}", f"|sleep {_SLEEP}", f"&&sleep {_SLEEP}",
    f"`sleep {_SLEEP}`", f"$(sleep {_SLEEP})", f"1;sleep {_SLEEP}",
)

_CMD_PARAMS = (
    "cmd", "exec", "command", "ping", "host", "ip", "query", "q", "search",
    "name", "dns", "domain", "address", "func", "action", "run", "system", "cli",
)


def detect_output(text: str, baseline: str = "") -> str | None:
    """Return the evidence kind if a command clearly executed, else None."""
    if _ID_RE.search(baseline) or _PRODUCT in baseline:
        return None
    if _ID_RE.search(text):
        return "id -> uid/gid"
    if _PRODUCT in text:
        return f"arithmetic -> {_PRODUCT}"
    return None


def _candidates(result, cap: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(url: str, param: str) -> None:
        parts = urllib.parse.urlsplit(url)
        key = (parts.netloc, parts.path, param)
        if key not in seen:
            seen.add(key)
            out.append((url, param))

    for url in result.urls:
        if not in_scope(url, result.target.host):
            continue
        for key, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True):
            add(url, key)

    base = result.target.base_url
    if base:
        for param in _CMD_PARAMS:
            add(base.rstrip("/") + "/", param)

    return out[:cap]


def _finding(result, url: str, param: str, method: str, evidence: str, resp=None) -> Finding:
    return Finding(
        title=f"OS command injection in parameter '{param}' ({method})",
        severity=Severity.CRITICAL,
        target=result.target.host,
        category="command-injection",
        location=url,
        description=(
            f"The '{param}' parameter is passed to a system shell: {evidence}. "
            "This allows arbitrary command execution on the server."
        ),
        remediation="Never pass user input to a shell; use argument arrays / safe APIs "
        "and strict input validation.",
        evidence=evidence,
        source=_SOURCE,
        extra={"parameter": param, "method": method},
        proof=build_proof(resp) if resp is not None else {},
    )


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    candidates = injpoints.build(result, result.target.host, base_param_names=_CMD_PARAMS, cap=20)
    if not candidates:
        return []

    baseline_cache = point_baselines(client, candidates, config.concurrency)
    findings: list[Finding] = []
    confirmed: set = set()

    # --- Output-based (parallel over points) ---
    def out_probe(point) -> Finding | None:
        for payload in _OUT_PAYLOADS:
            resp = injpoints.send(client, point, payload)
            if not resp.ok:
                continue
            kind = detect_output(resp.text, baseline_cache.get(injpoints.baseline_key(point), ""))
            if kind:
                return _finding(result, point.location, point.param, f"output/{point.kind}", kind, resp)
        return None

    for point, finding in parallel_map(out_probe, candidates, workers=config.concurrency):
        if finding is not None:
            confirmed.add(point.key())
            findings.append(finding)

    # --- Time-based (blind) --- only if the timeout leaves room for the sleep.
    if config.timeout >= _SLEEP + 2:
        time_points = [p for p in candidates[:6] if p.key() not in confirmed]

        def time_probe(point) -> Finding | None:
            base = injpoints.baseline(client, point)
            if not base.ok or base.elapsed > _SLEEP * 0.5:
                return None
            for payload in _TIME_PAYLOADS:
                resp = injpoints.send(client, point, payload)
                if resp.ok and resp.elapsed >= _SLEEP * 0.8 and (resp.elapsed - base.elapsed) >= _SLEEP * 0.7:
                    return _finding(
                        result, point.location, point.param, f"time/{point.kind}",
                        f"sleep {_SLEEP} delayed the response by ~{resp.elapsed:.1f}s", resp,
                    )
            return None

        for _p, finding in parallel_map(time_probe, time_points, workers=config.concurrency):
            if finding is not None:
                findings.append(finding)

    return findings
