"""Vulnerability-scan orchestrator: run every check, then normalise findings."""

from __future__ import annotations

from ..config import ScanConfig
from ..models import Finding, ScanResult
from ..scoring import score_finding
from ..utils.net import build_client
from . import (
    access_control,
    cmdinjection,
    cors,
    crlf,
    csrf,
    cve,
    default_creds,
    dirscan,
    email_security,
    exposed_services,
    exposures,
    graphql,
    headers,
    hostheader,
    injection,
    jwt,
    lfi,
    nosqli,
    nuclei_scan,
    openapi,
    prototype_pollution,
    redirect,
    secrets,
    ssrf,
    ssti,
    takeover,
    tls_checks,
    waf,
    xxe,
)

# Each check is ``check(result, config, client, ui) -> list[Finding]``.
_NATIVE_CHECKS = (
    ("WAF detection", waf.check),
    ("Security headers & cookies", headers.check),
    ("TLS configuration", tls_checks.check),
    ("Subdomain takeover", takeover.check),
    ("Exposed services", exposed_services.check),
    ("Known CVEs (version match)", cve.check),
    ("Email security (SPF/DMARC/DKIM)", email_security.check),
    ("Secrets in JavaScript", secrets.check),
    ("Exposed sensitive files", exposures.check),
    ("API spec (OpenAPI/Swagger)", openapi.check),
    ("Directory brute-force", dirscan.check),
    ("CORS misconfiguration", cors.check),
    ("Open redirect", redirect.check),
    ("Host-header injection", hostheader.check),
    ("CRLF injection", crlf.check),
    ("CSRF (missing token)", csrf.check),
    ("JWT weaknesses", jwt.check),
    ("GraphQL introspection", graphql.check),
    ("XXE", xxe.check),
    ("SSTI", ssti.check),
    ("LFI / path traversal", lfi.check),
    ("OS command injection", cmdinjection.check),
    ("Prototype pollution", prototype_pollution.check),
    ("NoSQL injection", nosqli.check),
    ("SSRF", ssrf.check),
    ("Injection probes", injection.check),
    ("Broken access control / IDOR", access_control.check),
    ("Default credentials", default_creds.check),
)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


# Checks that don't need the target's web server to be reachable.
_WEB_INDEPENDENT = {
    "TLS configuration", "Subdomain takeover", "Exposed services",
    "Known CVEs (version match)", "Secrets in JavaScript",
    "Email security (SPF/DMARC/DKIM)",
}


def _web_reachable(result: ScanResult, client) -> bool:
    """True if the target's web server actually answers (avoids blasting a dead host)."""
    if result.endpoints:
        return True
    base = result.target.base_url or f"http://{result.target.host}"
    return client.get(base).ok


def run(result: ScanResult, config: ScanConfig, ui) -> None:
    """Run all vulnerability checks and attach de-duplicated findings.

    Guards against pathological runtime: if the target's web server is not
    reachable, HTTP checks are skipped instead of timing out on every payload;
    and a global time budget stops the phase from running unbounded.
    """
    import time

    # Payload checks respond fast on a live host; cap the per-request timeout so
    # an unreachable/slow target can't stall each of hundreds of requests.
    client = build_client(config, timeout=min(config.timeout, 8.0))

    reachable = _web_reachable(result, client)
    if not reachable:
        ui.warn(
            "Target web server is not reachable — skipping HTTP vulnerability "
            "checks (running only host-independent checks)."
        )

    deadline = time.monotonic() + config.max_scan_seconds
    collected: list[Finding] = []
    for name, check in _NATIVE_CHECKS:
        if not reachable and name not in _WEB_INDEPENDENT:
            continue
        if time.monotonic() > deadline:
            ui.warn(
                f"Vulnerability-scan time budget ({config.max_scan_seconds:.0f}s) "
                "reached — skipping remaining checks (raise with --max-time)."
            )
            break
        try:
            found = check(result, config, client, ui)
        except Exception as exc:  # noqa: BLE001 - one check never sinks the scan
            result.errors.append(f"{name}: {exc}")
            found = []
        if found:
            ui.good(f"{name}: {len(found)} finding(s)")
        collected.extend(found)

    # nuclei last (it is the slowest and most prolific).
    if reachable and time.monotonic() <= deadline:
        try:
            collected.extend(nuclei_scan.check(result, config, client, ui))
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"nuclei: {exc}")

    if getattr(client, "was_throttled", False):
        ui.warn(
            "Target appears to be rate-limiting or blocking requests — Strix "
            "backed off automatically. Results may be incomplete; consider "
            "--stealth, a lower --rate-limit, waiting, or scanning from another IP."
        )
        result.errors.append("rate-limiting/blocking detected during scan")

    for finding in _dedupe(collected):
        score_finding(finding)
        result.add_finding(finding)
        ui.finding(finding.severity, finding.title, finding.location, cvss=finding.cvss_score)
