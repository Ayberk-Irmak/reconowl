"""Native check: exposed sensitive files and directories.

Uses a random-path baseline to detect "soft 404s" (sites that return 200 for
everything) so a hit is only reported when it differs from that baseline and
looks like the real thing.
"""

from __future__ import annotations

import urllib.parse

from ..models import Finding, Severity
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient, build_proof

_SOURCE = "native:exposure"

# path -> (title, severity, content signature that must appear to confirm)
_SENSITIVE_PATHS: dict[str, tuple[str, Severity, str]] = {
    ".git/HEAD": ("Exposed .git repository", Severity.HIGH, "ref:"),
    ".git/config": ("Exposed .git config", Severity.HIGH, "[core]"),
    ".env": ("Exposed .env file", Severity.HIGH, "="),
    ".svn/entries": ("Exposed .svn directory", Severity.MEDIUM, ""),
    ".DS_Store": ("Exposed .DS_Store", Severity.LOW, ""),
    "backup.zip": ("Exposed backup archive", Severity.HIGH, ""),
    "backup.sql": ("Exposed SQL backup", Severity.HIGH, ""),
    "db.sql": ("Exposed SQL dump", Severity.HIGH, ""),
    "wp-config.php.bak": ("Exposed wp-config backup", Severity.CRITICAL, ""),
    ".htpasswd": ("Exposed .htpasswd", Severity.HIGH, ":"),
    "config.php.bak": ("Exposed PHP config backup", Severity.HIGH, ""),
    "phpinfo.php": ("Exposed phpinfo()", Severity.MEDIUM, "phpinfo"),
    "server-status": ("Exposed Apache server-status", Severity.MEDIUM, "Server uptime"),
    ".well-known/security.txt": ("security.txt present", Severity.INFO, ""),
    "robots.txt": ("robots.txt present", Severity.INFO, ""),
}


def _exposure_category(severity: Severity) -> str:
    """Pick a category whose CVSS vector matches the finding's severity."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "exposure"          # C:H → 7.5, for .git/.env/backups
    if severity == Severity.INFO:
        return "info-file"         # → 0.0, for robots.txt/security.txt
    return "sensitive-file"        # severity fallback: Medium→5.4, Low→3.1


def _baseline(client: HttpClient, base: str) -> tuple[int | None, int]:
    """Fetch a random path to learn the site's 'not found' behaviour."""
    probe = urllib.parse.urljoin(base + "/", "reconowl-nonexistent-a9f3c1e7.html")
    resp = client.get(probe)
    length = len(resp.text) if resp.ok else 0
    return (resp.status if resp.ok else None), length


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    base = result.target.base_url
    if not base:
        return []

    base_status, base_len = _baseline(client, base)
    findings: list[Finding] = []

    def probe(item: tuple[str, tuple[str, Severity, str]]):
        path, (title, severity, signature) = item
        url = urllib.parse.urljoin(base + "/", path)
        resp = client.get(url)
        if not resp.ok or resp.status != 200:
            return None
        # Reject soft-404s: identical status AND near-identical length to baseline.
        if base_status == 200 and abs(len(resp.text) - base_len) < 32 and not signature:
            return None
        if signature and signature not in resp.text:
            return None
        return Finding(
            title=title,
            severity=severity,
            target=result.target.host,
            # Keep the CVSS consistent with the finding's severity: the high-impact
            # "exposure" vector (7.5) is only for High/Critical leaks (.git/.env/
            # backups); lower-severity files (.DS_Store, robots.txt) must not inherit it.
            category=_exposure_category(severity),
            location=url,
            description=f"{url} is reachable and returned HTTP 200.",
            remediation="Remove the file from the web root or block access to it.",
            evidence=(resp.text[:160].replace("\n", " ") if resp.text else ""),
            source=_SOURCE,
            proof=build_proof(resp),
        )

    for _item, finding in parallel_map(probe, _SENSITIVE_PATHS.items(), workers=config.concurrency):
        if finding is not None:
            findings.append(finding)
    return findings
