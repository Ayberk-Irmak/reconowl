"""Native check: email authentication posture (SPF / DMARC / DKIM).

Evaluates the registrable domain's anti-spoofing DNS records:

- **SPF** (`v=spf1` TXT on the domain) — missing, overly permissive (`+all`),
  weak (`?all` / no `all`), or duplicated (RFC-invalid).
- **DMARC** (`v=DMARC1` TXT at `_dmarc.<domain>`) — missing, monitor-only
  (`p=none`), or partially enforced (`pct<100`).
- **DKIM** — probes a handful of common selectors at
  `<selector>._domainkey.<domain>`; a domain with none found can't be confirmed
  to sign its mail (informational — selectors are arbitrary).

Missing/weak email authentication lets attackers spoof the domain in phishing.
Runs on DNS only, so it works even when the web server is unreachable.
"""

from __future__ import annotations

from ..models import Finding, ScanResult, Severity
from ..utils import dnsx
from ..utils.net import apex_domain

_SOURCE = "native:email-security"

# Common DKIM selectors used by mainstream providers / defaults.
_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "dkim",
    "mail", "s1", "s2", "mandrill", "smtp", "mx", "email", "zoho", "protonmail",
)


def _spf_records(txt: list[str]) -> list[str]:
    return [t for t in txt if t.lower().replace('"', "").strip().startswith("v=spf1")]


def _spf_all_qualifier(record: str) -> str:
    """Return the qualifier on the trailing ``all`` mechanism: +, -, ~, ?, or ''."""
    rec = record.lower().replace('"', "")
    for qual in ("-all", "~all", "?all", "+all"):
        if qual in rec:
            return qual[0]
    if " all" in rec or rec.rstrip().endswith("all"):
        return " "  # bare 'all' == '+all'
    return ""  # no all mechanism at all


def _eval_spf(domain: str, target: str, txt: list[str]) -> list[Finding]:
    spf = _spf_records(txt)
    if not spf:
        return [Finding(
            title="No SPF record",
            severity=Severity.MEDIUM, target=target, category="spf-missing",
            location=domain,
            description=f"{domain} publishes no SPF (v=spf1) record, so receivers "
            "cannot tell which servers may send mail as this domain — easing spoofing.",
            remediation="Publish an SPF TXT record ending in '-all' listing only "
            "authorized senders (e.g. 'v=spf1 include:_spf.provider.com -all').",
            evidence="no v=spf1 TXT record", source=_SOURCE,
        )]
    if len(spf) > 1:
        return [Finding(
            title="Multiple SPF records (invalid)",
            severity=Severity.MEDIUM, target=target, category="spf-multiple",
            location=domain,
            description=f"{domain} publishes {len(spf)} SPF records; RFC 7208 permits "
            "exactly one, so receivers treat SPF as permerror and skip it.",
            remediation="Merge into a single SPF TXT record.",
            evidence=" | ".join(spf)[:300], source=_SOURCE,
        )]
    qual = _spf_all_qualifier(spf[0])
    if qual == "+" or qual == " ":
        return [Finding(
            title="SPF allows all senders (+all)",
            severity=Severity.HIGH, target=target, category="spf-permissive",
            location=domain,
            description=f"{domain}'s SPF ends in '+all', authorizing any server to "
            "send mail as this domain — SPF provides no protection.",
            remediation="Replace '+all' with '-all' (hardfail) after listing senders.",
            evidence=spf[0][:300], source=_SOURCE,
        )]
    if qual in ("?", ""):
        detail = "'?all' (neutral)" if qual == "?" else "no 'all' mechanism"
        return [Finding(
            title="Weak SPF policy",
            severity=Severity.LOW, target=target, category="spf-weak",
            location=domain,
            description=f"{domain}'s SPF uses {detail}, so unauthorized senders are "
            "not rejected — receivers get no actionable fail result.",
            remediation="End the SPF record with '-all' (hardfail) or at least '~all'.",
            evidence=spf[0][:300], source=_SOURCE,
        )]
    return []  # '-all' or '~all' — acceptable


def _eval_dmarc(domain: str, target: str, records: list[str]) -> list[Finding]:
    dmarc = [r for r in records if "v=dmarc1" in r.lower().replace('"', "")]
    if not dmarc:
        return [Finding(
            title="No DMARC record",
            severity=Severity.MEDIUM, target=target, category="dmarc-missing",
            location=f"_dmarc.{domain}",
            description=f"{domain} publishes no DMARC policy, so even with SPF/DKIM "
            "there is no instruction to reject spoofed mail nor any reporting.",
            remediation="Publish '_dmarc.<domain>' TXT 'v=DMARC1; p=reject; rua=...' "
            "(start with p=none to monitor, then move to quarantine/reject).",
            evidence="no v=DMARC1 TXT at _dmarc." + domain, source=_SOURCE,
        )]
    rec = dmarc[0].replace('"', "")
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    policy = tags.get("p", "none")
    findings: list[Finding] = []
    if policy == "none":
        findings.append(Finding(
            title="DMARC policy is monitor-only (p=none)",
            severity=Severity.LOW, target=target, category="dmarc-weak",
            location=f"_dmarc.{domain}",
            description=f"{domain}'s DMARC uses 'p=none', which only reports abuse and "
            "does not tell receivers to quarantine or reject spoofed mail.",
            remediation="Raise the policy to 'p=quarantine' then 'p=reject' once "
            "legitimate senders are aligned.",
            evidence=rec[:300], source=_SOURCE,
        ))
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        findings.append(Finding(
            title=f"DMARC only enforced on {pct}% of mail (pct={pct})",
            severity=Severity.LOW, target=target, category="dmarc-weak",
            location=f"_dmarc.{domain}",
            description=f"{domain}'s DMARC 'pct={pct}' applies the policy to only part "
            "of the mail stream, leaving the rest unprotected.",
            remediation="Set 'pct=100' (the default) to enforce on all mail.",
            evidence=rec[:300], source=_SOURCE,
        ))
    return findings


def _eval_dkim(domain: str, target: str, timeout: float) -> list[Finding]:
    for selector in _DKIM_SELECTORS:
        txt = dnsx.resolve(f"{selector}._domainkey.{domain}", "TXT", timeout=timeout)
        if any("v=dkim1" in t.lower().replace('"', "") or "p=" in t.lower() for t in txt):
            return []  # DKIM present under a common selector — good enough
    return [Finding(
        title="No DKIM key found under common selectors",
        severity=Severity.INFO, target=target, category="dkim-not-found",
        location=f"_domainkey.{domain}",
        description=f"No DKIM key was found for {domain} under common selectors "
        f"({', '.join(_DKIM_SELECTORS[:6])}, …). DKIM selectors are arbitrary, so this "
        "is not conclusive, but the domain may not sign its outbound mail.",
        remediation="Confirm a DKIM key is published for the sending selector and that "
        "outbound mail is signed.",
        evidence="no v=DKIM1 under probed selectors", source=_SOURCE,
    )]


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    domain = apex_domain(result.target.host)
    target = result.target.host
    timeout = min(getattr(config, "timeout", 5.0), 5.0)

    # Only conclude "missing" when DNS actually works for this domain.
    ns = dnsx.resolve(domain, "NS", timeout=timeout)
    txt = dnsx.resolve(domain, "TXT", timeout=timeout)
    if not ns and not txt and not dnsx.resolve(domain, "A", timeout=timeout):
        ui.warn("Email security: DNS not resolvable — skipping SPF/DMARC/DKIM checks.")
        return []

    dmarc = dnsx.resolve(f"_dmarc.{domain}", "TXT", timeout=timeout)

    findings = _eval_spf(domain, target, txt)
    findings += _eval_dmarc(domain, target, dmarc)
    findings += _eval_dkim(domain, target, timeout)

    if findings:
        ui.good(f"Email security ({domain}): {len(findings)} issue(s)")
    return findings
