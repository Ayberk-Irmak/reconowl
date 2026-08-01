# reconowl

[![CI](https://github.com/Ayberk-Irmak/reconowl/actions/workflows/ci.yml/badge.svg)](https://github.com/Ayberk-Irmak/reconowl/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/reconowl)](https://pypi.org/project/reconowl/)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![checks](https://img.shields.io/badge/native%20checks-28-8a2be2)
![tests](https://img.shields.io/badge/tests-210-brightgreen)

**Recon → scan → report, in one command.** reconowl is a CLI penetration-testing
orchestrator: point it at a target and it runs passive + active reconnaissance,
a detailed vulnerability scan, and produces an HTML/JSON/Markdown report.

Its design goal is to *actually produce results*: it **orchestrates proven
engines** (nmap, nuclei, httpx, sqlmap) where they exist and **falls back to
reliable native checks** where they don't — so a scan is useful on a full Kali
box and on a bare Python install alike.

```
reconowl example.com -y
```

> ## ⚠️ Authorized use only
> reconowl performs active scanning and light exploitation probing. **Use it only
> against systems you own or are explicitly authorized in writing to test.**
> Unauthorized scanning is illegal in most jurisdictions. reconowl will not start a
> scan until you confirm authorization (interactively, or with `-y`/`--authorize`).
> You are solely responsible for how you use it.

## Example

A run against an authorized target looks like this (output abbreviated):

```text
      ,___,                              _
      (O,O)    _ _ ___ __ ___ _ _  _____ __ _| |
      /)__)   | '_/ -_) _/ _ \ ' \/ _ \ V  V / |
      -"-"-   |_| \___\__\___/_||_\___/\_/\_/|_|

  recon → scan → report   v0.3.1

╭ Phase 1 · Passive reconnaissance ╮
✓ DNS: A(1), MX(1), NS(2), TXT(3)     ✓ Subdomains: 4     ✓ Archived URLs: 118
╭ Phase 2 · Active reconnaissance ╮
✓ Open ports: 80/http, 443/https      ✓ Crawl: 22 pages, 9 forms
╭ Phase 3 · Vulnerability scanning ╮
✓ OpenAPI: parsed 31 operations from /openapi.json  (+18 URL, +6 form)
   HIGH    9.8  SQL injection (query: id)            https://target.tld/item?id=1
   HIGH    7.5  Reflected XSS (query: q)             https://target.tld/search?q=1
   MEDIUM  6.1  Missing security headers (CSP, HSTS) https://target.tld

Findings by severity:  Critical 0 · High 2 · Medium 5 · Low 3 · Info 7
✓ HTML/JSON/Markdown reports written to ./reconowl-report/
```

Every confirmed finding carries a CVSS score and the exact request/response that
proved it (auth headers redacted). *Values above are illustrative.*

## Proven detection

Against a deliberately vulnerable local app, the native injection checks confirm
real bugs and attach the request/response that proved each one:

| Finding | CVSS | Confirmed by |
| --- | --- | --- |
| OS command injection (`host`) | 9.8 Critical | `GET /ping?host=;id` → `uid=0(root) gid=0(root)` |
| SQL injection (`id`) | 9.8 High | `GET /item?id=1'` → `sqlite3.OperationalError: unrecognized token` |
| LFI / path traversal (`file`) | 7.5 High | `GET /read?file=../../../../etc/passwd` → `root:x:0:0:…` |
| Reflected XSS (`q`) | 6.1 Medium | injected marker reflected unencoded |

Each is confirmed only on real evidence (command output, a database error, a
target-file signature, an unencoded reflection) — never on reflection alone — so
false positives stay low. Findings are not reported from a matched banner or
version string.

## Features

**Phase 1 — Passive recon** (no packets to the target)
- DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA) with a **DNS-over-HTTPS fallback** so
  resolution works even on locked-down egress where UDP/53 is blocked.
- WHOIS/registration data via RDAP.
- Subdomain enumeration via certificate transparency (crt.sh).
- Historical URL harvesting via the Wayback Machine.

**Phase 2 — Active recon**
- Port/service/version scanning with **nmap** (or a built-in TCP connect scanner
  when nmap is absent).
- HTTP probing with **httpx** (or a native prober) — status, title, server, tech.
- TLS/certificate inspection (issuer, SANs, expiry, trust, protocol) — reads
  even invalid/self-signed certs.
- Content discovery from robots.txt and sitemap.xml, plus an **active crawler**
  that follows links and extracts **form parameters** (optionally seeded by
  `katana`) so the injection checks have real inputs to test.
- **JavaScript analysis**: fetches in-scope JS bundles and extracts referenced
  **endpoints** (feeding the injection checks) and **hard-coded secrets** (AWS,
  Google, Slack, GitHub, Stripe, private keys, JWTs, …), reported redacted.
- **SPA / JS rendering** (`--render`, auto-detected): when a target renders its
  links/forms client-side (React/Vue/Angular/Next/…), reconowl drives a headless
  browser (Playwright) to render seed pages, harvesting the rendered DOM **and**
  the **XHR/fetch API endpoints** the app calls — then feeds them to the checks.
  Auto-triggers only on SPA-like pages; degrades to static + JS-endpoint
  extraction when no browser is installed.

**Phase 3 — Vulnerability scanning**
- Native checks: missing security headers, insecure cookie flags, TLS problems
  (expired / self-signed / untrusted / weak protocol), version disclosure, and
  exposed sensitive files (`.git`, `.env`, backups, `phpinfo`, …) with soft-404
  filtering to cut false positives.
- **Exposed services**: flags internet-facing databases (MySQL, PostgreSQL,
  MongoDB, Redis, …), remote-access (RDP, VNC, SMB, Telnet, FTP), and admin
  panels (Plesk, cPanel, Webmin, phpMyAdmin, …) with risk-based severity.
- **WAF detection & adaptive throttling**: fingerprints WAFs/CDNs (or runs
  `wafw00f`), and automatically backs off — then stops — when the target starts
  rate-limiting/blocking, warning you (use `--stealth` for polite scanning).
- **Email authentication (SPF/DMARC/DKIM)**: evaluates the registrable
  domain's anti-spoofing DNS — missing/permissive (`+all`)/weak SPF, missing or
  monitor-only (`p=none`) DMARC, and DKIM presence across common selectors —
  so phishing-enabling gaps are caught (DNS-only, works even if the site is down).
- **OpenAPI / Swagger parsing**: discovers a published API spec (Swagger 2.0 /
  OpenAPI 3.x, JSON or YAML), enumerates every operation's path/query/body
  parameters, and feeds them to the injection checks (GET → query points,
  POST → form/JSON body points) — turning API docs into real test coverage.
  A publicly reachable spec is also reported as information disclosure.
- **Known-CVE mapping**: matches detected software versions (Server header, nmap
  banners, tech fingerprints) against a curated offline CVE database with
  version-range comparison, reporting each hit with its real CVSS and NVD link.
- **Directory/file brute-force**: a built-in wordlist (override with
  `--wordlist`) with soft-404 baselining so sites that answer 200 for everything
  don't flood results; flags directory listings, protected resources, and
  sensitive paths, and feeds discoveries back into later checks.
- **CORS misconfiguration**: reflected arbitrary origin, trusted `null` origin,
  and wildcard policies — escalated when credentials are also allowed.
- **Open redirect**: off-site redirect via common redirect parameters, confirmed
  only on an actual 3xx `Location` / meta-refresh to the attacker host.
- **Host-header injection**: bogus `Host` / `X-Forwarded-Host` reflected into a
  redirect or absolute URLs (cache / password-reset poisoning).
- **CRLF injection / response splitting**: a `\r\n`-and-marker payload confirmed
  only when the injected header (or cookie) actually appears in the response
  headers.
- **Subdomain takeover**: matches each subdomain's CNAME and page against a
  fingerprint database of 25+ third-party services; unique fingerprints stand
  alone while generic ones require a CNAME match, and dangling CNAMEs are flagged
  — keeping false positives low.
- **GraphQL introspection**: probes common GraphQL endpoints; flags enabled
  introspection (full-schema disclosure) and exposed GraphiQL/Playground IDEs.
- **XXE**: posts external-entity XML to XML-accepting endpoints, confirmed by an
  in-band `/etc/passwd` read or an out-of-band callback (reusing the SSRF
  listener) — zero-false-positive by construction.
- **JWT weaknesses**: harvests tokens from cookies/headers/bodies and analyses
  them offline — `alg:none`, brute-forced weak HMAC secrets (forgeable tokens),
  missing expiry, and sensitive data in the payload.
- **SSTI**: injects arithmetic template expressions for several engines
  (Jinja2/Twig, FreeMarker/EL, ERB, Razor, …) and confirms only when the
  *evaluated* product appears — strong signal for template injection (often RCE).
- **LFI / path traversal**: injects traversal payloads (multiple depths and
  encodings, Linux and Windows) into file-like parameters, confirmed only when a
  target file's signature (`/etc/passwd`, `win.ini`) appears in the response.
- **OS command injection**: output-based (`id` / arithmetic expansion) and
  blind time-based (`sleep`) detection — confirmed only on real command output
  or a measured delay, so no reflection false positives.
- **Server-side prototype pollution**: the Express `json spaces` gadget —
  confirmed only when polluting `__proto__` visibly changes a JSON endpoint's
  formatting (and the cosmetic change is restored afterward).
- **SSRF**: URL-shaped parameters tested two ways — an **out-of-band callback
  listener** for zero-false-positive confirmation (ideal for lab/internal, where
  the target can reach the scanner), plus **in-band signature detection** for
  cloud-metadata and `file://` reads. Tune with `--oob-host/--oob-port/--no-oob`.
- **NoSQL injection**: error-based (Mongo/Mongoose error signatures) plus an
  operator-differential probe (`[$ne]` vs `[$eq]`) that only fires when the
  backend actually parses the operators.
- **Default / weak credentials**: tries a small, conservative set of well-known
  credential pairs against HTTP Basic Auth realms (401→200 is definitive) and
  discovered login forms (each pair submitted with CSRF/hidden fields preserved,
  compared to a known-bad baseline to avoid false positives). `--no-default-creds`.
- **CSRF (missing token)**: flags state-changing POST forms whose fields carry
  no anti-CSRF token — gated on cookie posture, so forms already protected by
  `SameSite=Strict/Lax` session cookies are not reported (low false positives).
- **Broken access control / IDOR**: re-requests sensitive resources without a
  session (protected content reachable unauthenticated → BAC), tampers numeric
  IDs (different object returned → likely IDOR), and — with `--second-cookie` —
  confirms cross-user object access.
- Injection probes: error-based **SQL injection** and reflected **XSS**
  candidates, with optional **sqlmap** confirmation.
- **GET / POST-form / JSON body coverage**: SQLi/XSS, SSTI, OS command injection,
  NoSQL, and LFI test query parameters, `application/x-www-form-urlencoded` form
  fields, and JSON body fields alike — form parameters come from the crawler.
- **nuclei** template scanning across discovered endpoints.

**Subdomain deepening** (`--subdomains`)
- After passive recon discovers subdomains, the live ones are scanned with the
  full web-layer check suite (headers, cookies, TLS, exposures, CORS, open
  redirect, injection) and their findings merged into one report. Port scanning
  and nuclei are skipped per subdomain to keep a broad sweep practical; cap with
  `--max-subdomains`. Active payloads are **scope-limited** to the target and its
  sibling subdomains, never to unrelated hosts pulled from sitemaps or archives.

**Phase 4 — Reporting**
- A self-contained, styled **HTML** report, full **JSON** for automation,
  **Markdown** for notes/GitHub, and **SARIF 2.1.0** for CI / GitHub code
  scanning (`--formats sarif`). Findings are normalized, de-duplicated, and
  severity-scored.
- **CVSS v3.1** base score, rating, and vector on every finding (shown in the
  console and all three report formats); the summary reports the highest CVSS.
- **Request/response proof** captured for each confirmed finding (the exact
  triggering request and response, with cookies/tokens redacted), shown in the
  HTML and Markdown reports and stored in JSON.
- **Scan-to-scan diff**: `--diff <previous report.json>` shows what's new, fixed,
  and changed since a prior run (console + `diff.json`/`diff.md`); or diff two
  saved reports without scanning via `--diff-reports OLD.json NEW.json`.

**Authenticated scanning** — a cookie, bearer token, basic auth, or custom
headers (`--cookie / --bearer / --auth-basic / -H`) are attached to every request
so checks reach authenticated surface area — or let reconowl **log in for you**
(`--login-url/--login-user/--login-pass`) and crawl + scan the session.

## Requirements

- Python 3.10+
- Python packages (installed automatically with reconowl): rich, requests,
  dnspython, jinja2, cryptography.
- Optional external tools on `PATH` (reconowl auto-detects and degrades gracefully):
  `nmap`, `nuclei`, `httpx`, `katana`, `sqlmap`, `nikto`, `whatweb`, `wafw00f`,
  `whois`. All ship with Kali Linux.
- Optional **headless browser** for SPA/JS rendering: install the `render` extra
  (`pip install ".[render]"`) then `playwright install chromium`. Without it,
  reconowl falls back to static crawling.

## Install

**Kali / Debian / Ubuntu** — these mark the system Python as *externally managed*
(PEP 668), so a plain `pip install` is refused. Install reconowl as an isolated
CLI with **pipx** (recommended):

```bash
sudo apt install pipx        # if you don't have it
pipx install reconowl
pipx ensurepath              # puts ~/.local/bin on PATH — then reopen your shell
reconowl --help
```

Anywhere pip is allowed (other distros, or inside a virtualenv):

```bash
pip install reconowl
reconowl --help
```

Optional **headless browser** for SPA/JS rendering:

```bash
pipx install "reconowl[render]" --include-deps && playwright install chromium
```

From source (for development):

```bash
git clone https://github.com/Ayberk-Irmak/reconowl.git && cd reconowl
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
reconowl --help
```

## Usage

The examples below use the `reconowl` command; `python -m reconowl` is equivalent.

```bash
# Full pipeline (recon + scan + report), confirming authorization inline:
reconowl example.com -y

# Web app target, aggressive intensity, HTML report only:
reconowl https://target.tld -y -i aggressive --formats html

# Recon only, no active scanning:
reconowl target.tld -y --passive-only

# Native-only (don't call nmap/nuclei/etc.):
reconowl target.tld -y --no-external

# Also scan discovered subdomains:
reconowl target.tld -y --subdomains

# Confirm SQLi candidates with sqlmap, custom output dir:
reconowl "https://target.tld/item.php?id=1" -y --sqlmap -o ./engagement

# Diff this scan against a previous run:
reconowl target.tld -y --diff ./engagement/report.json

# Diff two saved reports without scanning:
reconowl --diff-reports old/report.json new/report.json
```

### Authenticated scanning

Send a session cookie, bearer token, or arbitrary headers so every check (native
and orchestrated `httpx`/`nuclei`/`sqlmap`) runs authenticated:

```bash
reconowl https://app.tld -y --cookie "session=eyJ...; role=admin"
reconowl https://api.tld -y --bearer "eyJhbGciOi..."
reconowl https://app.tld -y -H "X-Api-Key: abc123" -H "X-Env: staging"
reconowl https://app.tld -y --auth-basic admin:s3cr3t
```

**Automated form login** — reconowl fetches the login page, fills the form
(preserving CSRF/hidden fields), captures the session, and crawls + scans the
authenticated area (avoiding logout links to keep the session alive):

```bash
reconowl https://app.tld -y \
  --login-url https://app.tld/login --login-user admin --login-pass 's3cr3t'
# fields are auto-detected; override with --login-user-field / --login-pass-field,
# and confirm success with --login-check "Dashboard".
```

Key options: `-i/--intensity {light,normal,aggressive}`, `--formats html,json,md`,
`--no-nuclei`, `--sqlmap`, `--subdomains`, `--timeout`, `--concurrency`,
`--rate-limit`, `--doh`/`--no-doh`, `-q/--quiet`. See `--help` for all.

## Output

Reports are written to `reconowl-report/` (or `-o <dir>`):

```
reconowl-report/
  report.html   # styled, self-contained
  report.json   # full machine-readable result
  report.md     # Markdown summary
```

### CI / GitHub code scanning

Emit SARIF and upload it so findings appear in the repo's Security tab:

```bash
reconowl https://staging.tld -y --formats sarif -o out
```

```yaml
# .github/workflows/reconowl.yml (excerpt)
- run: reconowl "$TARGET" -y --formats sarif -o out
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: out/report.sarif
```

CVSS scores map to SARIF `security-severity`, so GitHub ranks the alerts.

## How it works

Every phase writes into one normalized result model; reports render purely from
that model, so adding a check or a report format never touches the others.
External tools are optional accelerators, not hard dependencies — the same scan
runs (with less depth) when they're missing. Networking is built to survive
restrictive environments: name resolution can transparently fall back to
DNS-over-HTTPS, and TLS/port checks connect by resolved IP while preserving SNI.

## Roadmap

- Optional Nmap NSE and WhatWeb enrichment in the report.
- Screenshot capture for discovered endpoints.
- PyPI release.

## License

Provided as-is for authorized security testing and education.
