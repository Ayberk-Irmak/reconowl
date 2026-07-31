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
    # Directory brute-force is deliberately LAST among native checks: it is the
    # most request-heavy and lowest-yield, so under a tight time budget the
    # high-value injection/exploitation checks above run first and this is what
    # gets truncated — not the other way around.
    ("Directory brute-force", dirscan.check),
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
        # An open 80/443 that nonetheless refuses HTTP is a strong "you are being
        # blocked / rate-limited" signal (WAF/fail2ban), not a dead site.
        web_ports_open = any(p.number in (80, 443, 8080, 8443) and p.state == "open"
                             for p in result.ports)
        if web_ports_open:
            msg = ("Web ports (80/443) are open but the server returned no HTTP "
                   "response — you are likely rate-limited or IP-blocked (WAF/fail2ban). "
                   "Skipping HTTP checks. Wait, use --stealth, or scan from another IP.")
        else:
            msg = ("Target web server is not reachable — skipping HTTP vulnerability "
                   "checks (running only host-independent checks).")
        ui.warn(msg)
        result.errors.append("scan incomplete: web server unreachable — "
                             + ("likely blocked/rate-limited; " if web_ports_open else "")
                             + "all HTTP checks skipped")

    deadline = time.monotonic() + config.max_scan_seconds
    collected: list[Finding] = []
    for idx, (name, check) in enumerate(_NATIVE_CHECKS):
        if not reachable and name not in _WEB_INDEPENDENT:
            continue
        if time.monotonic() > deadline:
            # Record exactly which checks did NOT run, so the report never reads
            # as complete when it was truncated.
            skipped = [n for n, _ in _NATIVE_CHECKS[idx:]
                       if reachable or n in _WEB_INDEPENDENT]
            ui.warn(
                f"Vulnerability-scan time budget ({config.max_scan_seconds:.0f}s) "
                f"reached — skipping {len(skipped)} remaining check(s): "
                f"{', '.join(skipped)} (raise with --max-time)."
            )
            result.errors.append(
                f"scan incomplete: time budget ({config.max_scan_seconds:.0f}s) reached, "
                f"{len(skipped)} check(s) skipped: {', '.join(skipped)}"
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
    elif reachable:
        result.errors.append("scan incomplete: time budget reached before nuclei scan")

    if getattr(client, "was_throttled", False):
        ui.warn(
            "Target appears to be rate-limiting or blocking requests — reconowl "
            "backed off automatically. Results may be incomplete; consider "
            "--stealth, a lower --rate-limit, waiting, or scanning from another IP."
        )
        result.errors.append("rate-limiting/blocking detected during scan")

    for finding in _dedupe(collected):
        score_finding(finding)
        result.add_finding(finding)
        ui.finding(finding.severity, finding.title, finding.location, cvss=finding.cvss_score)
