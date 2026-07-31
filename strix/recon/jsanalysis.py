"""JavaScript analysis — extract endpoints and hard-coded secrets from JS files.

Modern apps expose most of their API surface (and, too often, credentials) in
their bundled JavaScript. This fetches in-scope ``.js`` files and:

- pulls out referenced **endpoints/paths** (feeding the injection checks), and
- scans for **hard-coded secrets** (API keys, tokens, private keys), recorded on
  the result for the secrets check to report.
"""

from __future__ import annotations

import re
import urllib.parse

from ..config import ScanConfig
from ..models import ScanResult
from ..utils.concurrency import parallel_map
from ..utils.net import build_client, in_scope

# Quoted paths / absolute URLs referenced in JS.
_ENDPOINT_RE = re.compile(r"""["'`]((?:https?:)?/[A-Za-z0-9_\-./]{1,120}(?:\?[A-Za-z0-9_\-.=&%]{0,120})?)["'`]""")
_SKIP_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
             ".woff2", ".ttf", ".map", ".scss", ".less")
_PLACEHOLDERS = ("your", "example", "xxx", "placeholder", "changeme", "dummy",
                 "test", "0000", "<", "{{", "}}", "%s")

# (name, regex, severity). Severity names map to Finding severities later.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "High"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "High"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Medium"),
    ("Google OAuth Client", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "Low"),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "High"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "Medium"),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "High"),
    ("Stripe Live Key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"), "High"),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "High"),
    ("SendGrid API Key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "High"),
    ("Mailgun API Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "Medium"),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "High"),
    ("Firebase Cloud Messaging Key", re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"), "High"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b"), "Info"),
    ("Generic API key/secret", re.compile(
        r"""(?i)\b(?:api[_-]?key|apikey|secret|client_secret|access[_-]?token|auth[_-]?token|password)\b['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{12,64})['"]"""
    ), "Low"),
]


def extract_endpoints(text: str, page_url: str, host: str, cap: int = 200) -> list[str]:
    """Extract in-scope endpoints/URLs referenced in a JS file."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in _ENDPOINT_RE.findall(text or ""):
        raw = raw.strip()
        if raw.startswith("//"):
            raw = "https:" + raw
        absolute = urllib.parse.urljoin(page_url, raw)
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme not in ("http", "https") or not parts.path:
            continue
        if parts.path.lower().endswith(_SKIP_EXT):
            continue
        if not in_scope(absolute, host):
            continue
        clean = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        if clean not in seen:
            seen.add(clean)
            out.append(clean)
            if len(out) >= cap:
                break
    return out


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[0] + "***"
    return f"{value[:4]}…{value[-3:]} (len {len(value)})"


def extract_secrets(text: str, location: str) -> list[dict]:
    """Extract hard-coded secrets from JS text as recorded hits."""
    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for name, pattern, severity in SECRET_PATTERNS:
        for m in pattern.finditer(text or ""):
            value = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            low = value.lower()
            if any(ph in low for ph in _PLACEHOLDERS):
                continue
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "type": name,
                "match": _redact(value),
                "severity": severity,
                "location": location,
            })
    return hits


def run(result: ScanResult, config: ScanConfig, ui) -> None:
    """Fetch in-scope JS files, extract endpoints (→ urls) and secrets."""
    if not getattr(config, "js_analysis", True):
        return
    host = result.target.host
    js_urls = list(dict.fromkeys(
        result.js_files + [u for u in result.urls if urllib.parse.urlsplit(u).path.lower().endswith(".js")]
    ))
    js_urls = [u for u in js_urls if in_scope(u, host)][:60]
    if not js_urls:
        return

    ui.info(f"Analyzing {len(js_urls)} JavaScript file(s)…")
    client = build_client(config, timeout=min(config.timeout, 8.0))
    known = set(result.urls)
    new_endpoints = 0

    def fetch(url: str):
        resp = client.get(url)
        return resp if resp.ok else None

    for url, resp in parallel_map(fetch, js_urls, workers=config.concurrency):
        if resp is None:
            continue
        for ep in extract_endpoints(resp.text, url, host):
            if ep not in known and len(result.urls) < config.max_urls:
                known.add(ep)
                result.urls.append(ep)
                new_endpoints += 1
        result.secrets.extend(extract_secrets(resp.text, url))

    # De-duplicate secrets across files.
    unique = {(s["type"], s["match"]): s for s in result.secrets}
    result.secrets = list(unique.values())
    ui.good(f"JS analysis: {new_endpoints} new endpoint(s), {len(result.secrets)} secret(s)")
