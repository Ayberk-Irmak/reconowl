# Changelog

All notable changes to reconowl are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-08-03

### Added
- **Executive summary** in every report (HTML/Markdown/JSON): a data-driven prose
  narrative — finding counts, the highest-rated issue, key risk areas, WAF presence,
  and a coverage caveat when the scan was partial.
- **Scan-coverage panel**: the report now states plainly whether coverage was
  Complete or Partial, listing exactly what was skipped (time-budget/blocking/
  unreachable) so the *absence* of findings is never mistaken for a clean result.

### Fixed
- Exposure findings are now scored consistently with their severity (a Low
  `.DS_Store` no longer shows a 7.5 "High" CVSS): only High/Critical leaks
  (`.git`/`.env`/backups) keep the high-impact vector.

## [0.4.1] - 2026-08-03

### Fixed
- **Injection checks no longer miss real endpoints on targets with archive history.**
  Passive recon can harvest hundreds of Wayback URLs that were placed ahead of the
  freshly-crawled live URLs in `result.urls`; the per-check injection-point cap then
  spent itself on stale archive URLs and skipped real parameters (e.g. LFI and OS
  command injection on a live parameter went undetected). Crawler-discovered URLs
  are now tracked and prioritised over archive URLs when building injection points.
  Verified end-to-end against a vulnerable app with 300 harvested URLs: SQLi, XSS,
  LFI, and command injection are all detected again.

## [0.4.0] - 2026-08-03

### Added
- **`--profile` presets** (`quick`, `standard`, `deep`, `stealth`) bundle intensity,
  pacing, subdomain deepening, and the time budget into a single knob — pick one
  instead of juggling `-i`/`--stealth`/`--concurrency`/`--rate-limit`/`--max-time`/
  `--subdomains`. Every individual flag still overrides the profile, and the active
  profile is printed at the start of each scan. `--no-subdomains` added.

### Changed
- **`--max-time` is now a global budget** covering the whole vulnerability phase
  *including* subdomain deepening. Previously it applied per host, so `--subdomains`
  on a large target (e.g. 100+ subdomains) could run for hours; now the run stops
  starting new subdomains once the budget is reached and records how many were
  skipped.
- Subdomain deepening is lighter per host (shallow crawl, no directory brute-force)
  so a broad sweep stays practical.

## [0.3.1] - 2026-08-01

### Added
- Error-based SQL-injection detection now recognises **SQLite / Python** database
  errors (`sqlite3.OperationalError`, `unrecognized token`, SQLAlchemy) in
  addition to MySQL/Postgres/Oracle/MSSQL — validated end-to-end against a
  deliberately vulnerable local app (SQLi/XSS/LFI/command-injection all detected
  with request/response proof).
- CI now runs `ruff` linting (focused `E`/`F`/`I`/`UP`/`B` ruleset) alongside the
  test matrix; issue & PR templates, a `SECURITY.md` disclosure policy, an
  `Example` section in the README, and Dependabot for pip + GitHub Actions.

## [0.3.0] - 2026-07-31

### Changed
- **Renamed the project from `strix` to `reconowl`** to avoid a crowded namespace
  (multiple unrelated "Strix" security projects). The PyPI package is now
  `reconowl` (`pip install reconowl`), the CLI command is `reconowl`, and the repo
  is `github.com/Ayberk-Irmak/reconowl`. No functional changes — same 28 native
  checks and pipeline. The former `strix-scanner` package is discontinued.

## [0.2.1] - 2026-07-31

### Fixed
- Scan truncation is no longer silent: when the vuln-scan time budget is reached,
  or the web server is unreachable, the skipped checks are recorded in the report
  (`errors`). When web ports (80/443/8080/8443) are open but the server returns no
  HTTP response, reconowl now reports a likely rate-limit/IP-block instead of a bare
  "unreachable".
- Directory brute-force now runs **last** among native checks, so under a tight
  time budget the high-value injection/exploitation checks run first and the
  request-heavy brute-force is what gets truncated — not the other way around.
- `robots.txt` / `security.txt` are no longer scored with the high-impact
  "exposure" CVSS vector (7.5 → INFO/0.0), and benign accessible paths from the
  directory scan no longer masquerade as mid-severity noise at the top of reports.

## [0.2.0] - 2026-07-31

### Added
- OpenAPI/Swagger discovery & parsing: finds a published API spec (Swagger 2.0 /
  OpenAPI 3.x, JSON or YAML), enumerates operations and their path/query/body
  parameters, and feeds them to the injection checks (GET→query, POST→form/JSON).
  A reachable spec is reported as information disclosure. `--no-openapi`.
- SPA / headless JS rendering (`--render`/`--no-render`, auto by default):
  renders seed pages with Playwright when a target is client-rendered, recovering
  links, forms, and the XHR/fetch API endpoints the app calls (fed to the checks).
  Auto-triggers only on SPA-like shells; degrades gracefully with no browser.
- CSRF check: state-changing POST forms without an anti-CSRF token field are
  flagged, gated on cookie posture (SameSite=Strict/Lax cookies suppress the finding).
  `--no-csrf` to disable.
- Email authentication check (SPF/DMARC/DKIM): evaluates the registrable
  domain's anti-spoofing DNS posture — missing/permissive/weak SPF, missing or
  monitor-only DMARC, and DKIM presence across common selectors. DNS-only.
- Default/weak-credentials check: a small, conservative set of common credential
  pairs is tried against HTTP Basic Auth realms (401→200 is definitive) and
  discovered login forms (CSRF/hidden fields preserved, compared to a known-bad
  baseline); hits are CRITICAL. `--no-default-creds` to disable.
- WAF/CDN detection (wafw00f + native fingerprinting) and adaptive rate-limit
  handling: reconowl backs off, then gives up hammering, when the target blocks or
  rate-limits, and warns the operator. `--stealth` mode and `--no-adaptive`.
- Request/response proof capture: each confirmed finding records the exact
  triggering HTTP request and response (auth headers/cookies redacted), rendered
  in the HTML and Markdown reports and included in JSON.
- Broken access control / IDOR check: unauthenticated access to sensitive
  resources (when a session is configured), numeric ID tampering, and confirmed
  cross-user object access via `--second-cookie`.
- Version→CVE mapping: detected software versions (Server header, nmap banners,
  tech fingerprints) are matched against a curated offline CVE database via
  version-range comparison; hits are reported with the CVE's real CVSS and an NVD
  reference. Toggle with `--no-cve`.
- JavaScript analysis: fetches in-scope JS files, extracts referenced endpoints
  (fed to the injection checks) and hard-coded secrets (AWS/Google/Slack/GitHub/
  Stripe/private keys/JWT/generic), reported redacted with risk-based severity.
  Toggle with `--no-js`.
- Automated form login (`--login-url/--login-user/--login-pass`, optional
  `--login-*-field`/`--login-check`): fills the login form (preserving CSRF/hidden
  fields), captures the session, and runs the crawl + all checks authenticated;
  the crawler avoids logout links to keep the session alive.
- POST-form and JSON body injection testing: SQLi/XSS, SSTI, OS command
  injection, NoSQL, and LFI now test query params, form fields, and JSON body
  fields through a shared injection-point abstraction; form parameters are
  discovered by the crawler.
- Authenticated scanning: `--cookie`, `--bearer`, `--auth-basic`, and repeatable
  `-H/--header` attach credentials to every native check and to orchestrated
  httpx/nuclei/sqlmap.
- SARIF 2.1.0 report export (`--formats sarif`) with CVSS mapped to
  `security-severity` for GitHub code scanning.

- Exposed-services check: internet-facing databases, remote-access services, and
  admin panels are reported as risk-scored findings.
- Active crawler: follows in-scope links and extracts form parameters (optionally
  seeded by `katana`) so injection checks have real inputs; `--no-crawl`,
  `--crawl-depth`, `--crawl-pages`.

- Parallelized the injection-family checks (SQLi/XSS, CRLF, SSTI, LFI, OS command
  injection, NoSQL, SSRF/XXE in-band, open redirect): candidates are now probed
  concurrently (`--concurrency`) with baselines pre-fetched in parallel, cutting
  the vuln phase from minutes to seconds against concurrent-capable servers.

### Fixed
- Registrable-domain (eTLD+1) resolution now handles multi-label public
  suffixes (`com.tr`, `co.uk`, `com.au`, …): scope filtering no longer treats every
  `*.com.tr` as in-scope, and email-auth lookups target the real domain.
- Crawler no longer skips crawling when passive recon already filled the URL cap
  (e.g. a 300-URL Wayback dump): it now runs on a page budget and adds live URLs
  on top of passive ones, restoring form/JS discovery on archive-heavy targets.
- Vulnerability phase no longer runs for hours against an unreachable/slow
  target: a reachability gate skips HTTP checks when the web server doesn't
  answer, a `--max-time` budget bounds the phase, and payload requests use a
  lower timeout.

## [0.1.0] - 2026-07-30

Initial release.

### Recon
- Passive: DNS (with DNS-over-HTTPS fallback), RDAP/WHOIS, certificate-transparency
  subdomains (Cert Spotter + crt.sh), Wayback URL harvesting.
- Active: nmap (or native TCP) port/service scan, httpx (or native) HTTP probing,
  TLS/certificate inspection, robots/sitemap content discovery.
- Subdomain deepening (`--subdomains`) with scope-limited active testing.

### Vulnerability checks (native + orchestrated)
- Security headers & cookies, TLS misconfigurations, exposed sensitive files,
  directory brute-force (soft-404 aware).
- CORS misconfiguration, open redirect, host-header injection, CRLF injection.
- SSRF (out-of-band + in-band), XXE (OOB + in-band), SSTI, LFI/path traversal,
  OS command injection (output + blind time-based).
- Prototype pollution (json-spaces gadget), NoSQL injection (error + operator
  differential), SQLi/XSS probes, JWT weaknesses (alg:none, weak-secret crack,
  no-exp, sensitive claims), GraphQL introspection/IDE exposure, subdomain takeover.
- nuclei and sqlmap orchestration when available.

### Scoring & reporting
- CVSS v3.1 base score, rating, and vector on every finding.
- HTML, JSON, and Markdown reports.
- Scan-to-scan diff (`--diff`, `--diff-reports`).

### Reliability
- DoH-based resolution works behind restrictive egress.
- Scope filter keeps active payloads on the target and its sibling subdomains.
- 114 tests.
