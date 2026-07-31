"""Native check: subdomain takeover.

For every discovered subdomain, resolve its CNAME chain and fetch its page. A
subdomain is a takeover candidate when either:

- its page carries a third-party service's *unclaimed-resource* fingerprint
  (e.g. GitHub Pages' "There isn't a GitHub Pages site here."), or
- it has a CNAME to a known service whose target no longer resolves (a dangling
  DNS record).

Both are high-signal: those exact fingerprint strings only appear on unclaimed
resources, and a dangling CNAME to a claimable service is directly exploitable.
"""

from __future__ import annotations

import json
import os

from ..models import Finding, Severity
from ..utils import dnsx
from ..utils.concurrency import parallel_map
from ..utils.net import HttpClient

_SOURCE = "native:takeover"
_FINGERPRINTS = os.path.join(os.path.dirname(__file__), "..", "data", "takeover_fingerprints.json")

_MAX_SUBDOMAINS = 100


def load_fingerprints(path: str = "") -> list[dict]:
    try:
        with open(path or _FINGERPRINTS, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def analyze(
    cnames: list[str], body: str, resolvable: bool, fingerprints: list[dict]
) -> tuple[str, str] | None:
    """Return ``(service, reason)`` for a takeover candidate, else None.

    ``reason`` is "fingerprint" (page matched an unclaimed-resource string) or
    "dangling-cname" (CNAME to a known service that no longer resolves).
    """
    cnames = [c.lower().rstrip(".") for c in cnames]
    low_body = body.lower()

    def cname_matches(fp: dict) -> bool:
        return any(pat.lower() in c for c in cnames for pat in fp.get("cnames", []))

    # Fingerprint in the page body. A globally-unique fingerprint stands alone;
    # a generic one ("page not found", "404 Not Found") only counts when the
    # CNAME also points at that service — otherwise any 404 page would match.
    for fp in fingerprints:
        needle = (fp.get("fingerprint") or "").lower()
        if needle and needle in low_body and (fp.get("unique") or cname_matches(fp)):
            return fp.get("service", "unknown"), "fingerprint"

    # Dangling CNAME to a known service (target no longer resolves).
    if not resolvable:
        for fp in fingerprints:
            if cname_matches(fp):
                return fp.get("service", "unknown"), "dangling-cname"
    return None


def check(result, config, client: HttpClient, ui) -> list[Finding]:
    hosts = list(dict.fromkeys([result.target.host, *result.subdomains]))
    hosts = [h for h in hosts if h][:_MAX_SUBDOMAINS]
    if not hosts:
        return []

    fingerprints = load_fingerprints()
    if not fingerprints:
        return []
    ui.info(f"Checking {len(hosts)} host(s) for subdomain takeover…")

    def probe(host: str):
        cnames = dnsx.resolve(host, "CNAME")
        resolvable = bool(dnsx.resolve_ip(host))
        body = ""
        for scheme in ("https", "http"):
            resp = client.get(f"{scheme}://{host}")
            if resp.ok:
                body = resp.text
                break
        return cnames, resolvable, analyze(cnames, body, resolvable, fingerprints)

    findings: list[Finding] = []
    for host, res in parallel_map(probe, hosts, workers=config.concurrency):
        if res is None:
            continue
        cnames, _resolvable, verdict = res
        if verdict is None:
            continue
        service, reason = verdict
        findings.append(
            Finding(
                title=f"Possible subdomain takeover ({service})",
                severity=Severity.HIGH,
                target=result.target.host,
                category="subdomain-takeover",
                location=host,
                description=(
                    f"'{host}' points at {service} via a "
                    + ("dangling CNAME whose target no longer resolves"
                       if reason == "dangling-cname"
                       else "resource whose page shows an unclaimed-service fingerprint")
                    + " — an attacker may be able to claim it and serve content on "
                    "this subdomain."
                ),
                remediation="Remove the dangling DNS record, or re-claim the resource "
                f"on {service}.",
                evidence=f"reason={reason}"
                + (f"; CNAME={', '.join(cnames)}" if cnames else ""),
                source=_SOURCE,
                extra={"service": service, "reason": reason, "cnames": cnames},
            )
        )
    return findings
