"""Native check: directory / file brute-forcing.

Requests a wordlist of common paths against the target and reports the ones that
exist. A per-target baseline (several random paths) profiles how the site answers
"not found" — status, body length, and redirect target — so soft-404s (sites
that return 200 or redirect for everything) don't drown the results in noise.

Discovered paths are also fed back into ``result.urls`` so later checks can use
them.
"""

from __future__ import annotations

import os
import secrets
import urllib.parse
from dataclasses import dataclass, field

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient

_SOURCE = "native:dirscan"
_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "wordlists", "common.txt")

# Length tolerance when comparing a 200 hit to the soft-404 baseline.
_LEN_TOLERANCE = 64

# Path substrings that make a discovered 200 more noteworthy.
_SENSITIVE = (
    "admin", "login", "config", "backup", "\\.git", "\\.env", "db", "sql",
    "secret", "cred", "passwd", "password", "phpmyadmin", "adminer", "console",
    "actuator", "key", "token", "private", "dump", "wp-config",
)


def load_wordlist(path: str = "") -> list[str]:
    """Load a wordlist (custom ``path`` or the built-in one), skipping comments."""
    target = path or _WORDLIST
    try:
        with open(target, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    words: list[str] = []
    seen: set[str] = set()
    for line in lines:
        w = line.strip()
        if not w or w.startswith("#") or w in seen:
            continue
        seen.add(w)
        words.append(w)
    return words


@dataclass
class _Baseline:
    statuses: set[int] = field(default_factory=set)
    lengths: list[int] = field(default_factory=list)
    locations: set[str] = field(default_factory=set)

    def looks_like_not_found(self, status: int, length: int, location: str) -> bool:
        """True if this response matches the site's generic 'not found' answer."""
        if status not in self.statuses:
            return False
        if status in (301, 302, 303, 307, 308):
            return _norm_location(location) in self.locations
        if status == 200:
            return any(abs(length - b) <= _LEN_TOLERANCE for b in self.lengths)
        # Same non-200 status as the random baseline (e.g. everything is 403).
        return True


def _norm_location(location: str) -> str:
    """Path+query of a redirect target, host-independent, for comparison."""
    if not location:
        return ""
    parts = urllib.parse.urlsplit(location)
    return parts.path + ("?" + parts.query if parts.query else "")


def _build_baseline(client: HttpClient, base: str) -> _Baseline:
    bl = _Baseline()
    probes = [
        f"reconowl-nx-{secrets.token_hex(6)}",
        f"reconowl-nx-{secrets.token_hex(6)}/",
        f"reconowl-nx-{secrets.token_hex(6)}.html",
    ]
    for p in probes:
        resp = client.get(urllib.parse.urljoin(base + "/", p), allow_redirects=False)
        if not resp.ok or resp.status is None:
            continue
        bl.statuses.add(resp.status)
        bl.lengths.append(len(resp.text))
        loc = _norm_location(resp.header("location"))
        if loc:
            bl.locations.add(loc)
    return bl


def _classify(word: str, url: str, status: int, text: str) -> Finding | None:
    low_word = word.lower()
    listing = ("index of /" in text.lower() or "<title>directory listing" in text.lower())

    if listing:
        return Finding(
            title=f"Directory listing enabled: /{word}",
            severity=Severity.MEDIUM,
            target="",
            category="dir-listing",
            location=url,
            description=f"{url} returns an auto-generated directory index, exposing "
            "the file listing.",
            remediation="Disable automatic directory indexing (e.g. 'Options -Indexes').",
            source=_SOURCE,
        )

    if status in (401, 403):
        return Finding(
            title=f"Protected resource found: /{word}",
            severity=Severity.INFO,
            target="",
            category="dir-protected",
            location=url,
            description=f"{url} exists but is access-protected (HTTP {status}).",
            remediation="Confirm the resource should exist and is correctly restricted.",
            evidence=f"HTTP {status}",
            source=_SOURCE,
        )

    sensitive = any(s.strip("\\") in low_word for s in _SENSITIVE)
    if status in (200, 204, 301, 302, 307, 308, 500):
        return Finding(
            title=f"Accessible path: /{word}",
            severity=Severity.LOW if sensitive else Severity.INFO,
            target="",
            # Sensitive hits keep the scored "dir-" vector; benign accessible paths
            # (/images, /robots.txt, …) use a category that scores INFO/0.0 so they
            # don't masquerade as mid-severity noise at the top of the report.
            category="dir-found-sensitive" if sensitive else "path-accessible",
            location=url,
            description=f"{url} is reachable (HTTP {status}).",
            remediation="Verify the path should be publicly reachable.",
            evidence=f"HTTP {status}",
            source=_SOURCE,
        )
    return None


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    if not getattr(config, "dirbrute", True):
        return []
    base = result.target.base_url
    if not base:
        return []

    words = load_wordlist(getattr(config, "wordlist", "") or "")
    if not words:
        return []
    if config.intensity == "light":
        words = words[:120]

    baseline = _build_baseline(client, base)
    ui.info(f"Directory brute-force: {len(words)} paths…")

    def probe(word: str):
        url = urllib.parse.urljoin(base + "/", word)
        resp = client.get(url, allow_redirects=False)
        if not resp.ok or resp.status is None or resp.status == 404:
            return None
        if baseline.looks_like_not_found(resp.status, len(resp.text), resp.header("location")):
            return None
        return (url, resp.status, resp.text[:400])

    findings: list[Finding] = []
    for word, res in parallel_map(probe, words, workers=config.concurrency):
        if res is None:
            continue
        url, status, snippet = res
        if url not in result.urls:
            result.urls.append(url)
        finding = _classify(word, url, status, snippet)
        if finding is not None:
            finding.target = result.target.host
            finding.proof = {"request": f"GET {url}", "response": f"HTTP {status}\n\n{snippet}"}
            findings.append(finding)
    return findings
