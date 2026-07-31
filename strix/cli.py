"""Command-line entry point: parse args, gate on authorization, run phases."""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import urllib.parse
from datetime import datetime, timezone

from . import __version__, diffing
from .config import ScanConfig
from .console import UI
from .models import ScanResult, Target
from .recon import active, passive
from .report import write as write_reports
from .scan import engine as scan_engine
from . import subscan
from .utils import dnsx
from .utils.tools import available_tools


def parse_target(raw: str) -> Target:
    """Parse a domain / URL / IP into a :class:`Target`."""
    raw = raw.strip()
    candidate = raw if "://" in raw else "//" + raw
    parts = urllib.parse.urlsplit(candidate, scheme="")
    host = parts.hostname or raw
    scheme = parts.scheme or "https"

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    base_url = ""
    if "://" in raw:
        base_url = f"{parts.scheme}://{parts.netloc}"

    return Target(
        raw=raw,
        host=host,
        base_url=base_url,
        ip=host if is_ip else "",
        is_ip=is_ip,
        scheme=scheme,
    )


def build_auth_headers(args: argparse.Namespace) -> dict[str, str]:
    """Assemble request headers from -H / --bearer / --auth-basic flags."""
    import base64

    headers: dict[str, str] = {}
    for raw in args.header or []:
        if ":" in raw:
            name, value = raw.split(":", 1)
            headers[name.strip()] = value.strip()
    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer}"
    if args.auth_basic:
        token = base64.b64encode(args.auth_basic.encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def build_config(args: argparse.Namespace) -> ScanConfig:
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    concurrency, rate_limit, jitter = args.concurrency, args.rate_limit, 0.0
    if args.stealth:  # polite defaults for touchy targets / WAFs
        concurrency = min(concurrency, 3)
        rate_limit = rate_limit or 2.0
        jitter = 0.4
    return ScanConfig(
        target=args.target,
        passive=not args.no_passive,
        active=not args.no_active and not args.passive_only,
        vuln=not args.no_vuln and not args.passive_only,
        authorized=args.authorize,
        intensity=args.intensity,
        include_subdomains=args.subdomains,
        max_subdomains=args.max_subdomains,
        max_urls=args.max_urls,
        crawl=not args.no_crawl,
        crawl_depth=args.crawl_depth,
        crawl_max_pages=args.crawl_pages,
        render_mode=args.render_mode,
        render_max_pages=args.render_pages,
        js_analysis=not args.no_js,
        cve_lookup=not args.no_cve,
        default_creds=not args.no_default_creds,
        csrf_check=not args.no_csrf,
        openapi=not args.no_openapi,
        timeout=args.timeout,
        concurrency=concurrency,
        max_scan_seconds=args.max_time,
        rate_limit=rate_limit,
        jitter=jitter,
        adaptive=not args.no_adaptive,
        extra_headers=build_auth_headers(args),
        cookie=args.cookie,
        login_url=args.login_url,
        login_user=args.login_user,
        login_pass=args.login_pass,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        login_check=args.login_check,
        second_cookie=args.second_cookie,
        use_external=not args.no_external,
        run_nuclei=not args.no_nuclei,
        run_sqlmap=args.sqlmap,
        dirbrute=not args.no_dirbrute,
        wordlist=args.wordlist,
        ssrf_oob=not args.no_oob,
        oob_host=args.oob_host,
        oob_port=args.oob_port,
        output_dir=args.output,
        formats=formats,
        quiet=args.quiet,
        no_color=args.no_color,
    )


def confirm_authorization(target: str, ui: UI, assume_yes: bool) -> bool:
    """Offensive tooling must be gated on explicit operator consent."""
    if assume_yes:
        return True
    ui.warn(
        "Strix performs active scanning. Only test systems you own or are "
        "explicitly authorized to assess."
    )
    try:
        answer = input(f"  Confirm you are authorized to test '{target}'? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def _setup_dns(args: argparse.Namespace, ui: UI) -> None:
    if args.no_doh:
        return
    if args.doh:
        dnsx.enable_doh_socket("doh")
        ui.info("DNS: DoH-first resolution enabled.")
        return
    # Auto: fall back to DoH-capable resolver when the OS resolver looks unhealthy.
    if not dnsx.system_healthy():
        dnsx.enable_doh_socket("smart")
        ui.info("DNS: OS resolver unreliable — enabled resilient (DoH) resolution.")
    else:
        dnsx.enable_doh_socket("smart")


def run(args: argparse.Namespace) -> int:
    ui = UI(quiet=args.quiet, no_color=args.no_color)

    if args.diff_reports:
        return run_diff_only(args.diff_reports[0], args.diff_reports[1], ui)

    ui.banner()

    if not args.target:
        ui.error("A target is required (or use --diff-reports OLD NEW).")
        return 2

    config = build_config(args)
    target = parse_target(args.target)

    ui.info(f"Target: {target.raw}  (host={target.host}{', IP' if target.is_ip else ''})")
    tools = available_tools()
    detected = [n for n, p in tools.items() if p]
    ui.info(f"External tools detected: {', '.join(detected) if detected else 'none (native-only mode)'}")
    if config.is_authenticated():
        ui.info(f"Authentication: enabled ({len(config.build_headers())} header(s) sent per request)")

    if not confirm_authorization(target.raw, ui, config.authorized):
        ui.error("Authorization not confirmed. Aborting.")
        return 2

    _setup_dns(args, ui)

    if config.has_login():
        from .recon import login

        cookies = login.perform_login(config, ui)
        if cookies:
            config.cookie = login.cookies_to_header(cookies, config.cookie)
        else:
            ui.warn("Continuing unauthenticated.")

    result = ScanResult(target=target)

    if config.passive:
        ui.phase("Phase 1 · Passive reconnaissance")
        try:
            passive.run(result, config, ui)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"passive: {exc}")
            ui.error(f"Passive recon error: {exc}")

    if config.active:
        ui.phase("Phase 2 · Active reconnaissance")
        try:
            active.run(result, config, ui)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"active: {exc}")
            ui.error(f"Active recon error: {exc}")

    if config.vuln:
        ui.phase("Phase 3 · Vulnerability scanning")
        try:
            scan_engine.run(result, config, ui)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"scan: {exc}")
            ui.error(f"Scan error: {exc}")

    if config.include_subdomains and (config.active or config.vuln):
        ui.phase("Phase 3b · Subdomain deepening")
        try:
            subscan.run(result, config, ui)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"deepening: {exc}")
            ui.error(f"Subdomain deepening error: {exc}")

    result.finished_at = datetime.now(timezone.utc).isoformat()

    ui.phase("Phase 4 · Reporting")
    written = write_reports(result, config.output_dir, config.formats)
    for fmt, path in written.items():
        ui.good(f"{fmt.upper()} report: {path}")

    if args.diff:
        _run_scan_diff(result, args.diff, config.output_dir, ui)

    ui.summary(result)
    return 0


def _run_scan_diff(result: ScanResult, previous: str, output_dir: str, ui: UI) -> None:
    """Diff the just-finished scan against a previous JSON report."""
    if not os.path.exists(previous):
        ui.warn(f"--diff: previous report not found: {previous}")
        return
    try:
        old = diffing.load_report_findings(previous)
    except (OSError, ValueError) as exc:
        ui.warn(f"--diff: could not read {previous}: {exc}")
        return
    new = result.to_dict()["findings"]
    dr = diffing.diff_findings(old, new)
    ui.diff(dr, previous)
    diffing.write_json(dr, os.path.join(output_dir, "diff.json"))
    diffing.write_markdown(dr, os.path.join(output_dir, "diff.md"), previous, "current scan")
    ui.good(f"Diff report: {os.path.join(output_dir, 'diff.json')}")


def run_diff_only(old_path: str, new_path: str, ui: UI) -> int:
    """Diff two existing JSON reports without scanning."""
    for path in (old_path, new_path):
        if not os.path.exists(path):
            ui.error(f"Report not found: {path}")
            return 2
    old = diffing.load_report_findings(old_path)
    new = diffing.load_report_findings(new_path)
    dr = diffing.diff_findings(old, new)
    ui.diff(dr, old_path)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="strix",
        description="Strix — recon-to-report offensive security orchestrator "
        "for authorized penetration testing.",
        epilog="Only scan systems you own or are explicitly authorized to test.",
    )
    p.add_argument("target", nargs="?", help="Target domain, URL, or IP address.")
    p.add_argument("-y", "--authorize", action="store_true",
                   help="Confirm authorization non-interactively.")
    p.add_argument("-i", "--intensity", choices=["light", "normal", "aggressive"],
                   default="normal", help="Scan intensity (default: normal).")
    p.add_argument("-o", "--output", default="strix-report",
                   help="Output directory for reports (default: strix-report).")
    p.add_argument("--formats", default="html,json,md",
                   help="Comma-separated report formats: html,json,md,sarif.")
    p.add_argument("--diff", metavar="PREV_JSON", default="",
                   help="Diff this scan against a previous report.json.")
    p.add_argument("--diff-reports", nargs=2, metavar=("OLD_JSON", "NEW_JSON"),
                   help="Diff two existing JSON reports and exit (no scan).")

    p.add_argument("--passive-only", action="store_true", help="Run passive recon only.")
    p.add_argument("--no-passive", action="store_true", help="Skip passive recon.")
    p.add_argument("--no-active", action="store_true", help="Skip active recon.")
    p.add_argument("--no-vuln", action="store_true", help="Skip vulnerability scanning.")

    p.add_argument("--no-external", action="store_true",
                   help="Native checks only; do not call nmap/nuclei/etc.")
    p.add_argument("--no-nuclei", action="store_true", help="Do not run nuclei.")
    p.add_argument("--sqlmap", action="store_true",
                   help="Confirm SQLi candidates with sqlmap (slow).")
    p.add_argument("--no-dirbrute", action="store_true",
                   help="Disable directory/file brute-forcing.")
    p.add_argument("--wordlist", default="",
                   help="Custom wordlist for directory brute-forcing.")
    p.add_argument("--no-oob", action="store_true",
                   help="Disable the SSRF out-of-band callback listener.")
    p.add_argument("--oob-host", default="",
                   help="Reachable host for SSRF callbacks (default: auto-detect).")
    p.add_argument("--oob-port", type=int, default=0,
                   help="SSRF callback listener port (default: ephemeral).")
    p.add_argument("--subdomains", action="store_true",
                   help="Also scan discovered subdomains (broader, slower).")
    p.add_argument("--max-subdomains", type=int, default=25,
                   help="Max subdomains to deepen into (default: 25).")

    auth = p.add_argument_group("authentication")
    auth.add_argument("-H", "--header", action="append", metavar="'Name: Value'",
                      help="Custom request header (repeatable). Sent on every request.")
    auth.add_argument("--cookie", default="", metavar="'k=v; k2=v2'",
                      help="Cookie header value for authenticated scanning.")
    auth.add_argument("--bearer", default="", metavar="TOKEN",
                      help="Shortcut for 'Authorization: Bearer <TOKEN>'.")
    auth.add_argument("--auth-basic", default="", metavar="user:pass",
                      help="HTTP Basic auth credentials.")
    auth.add_argument("--login-url", default="", metavar="URL",
                      help="Login page/endpoint URL for automated form login.")
    auth.add_argument("--login-user", default="", help="Username for login.")
    auth.add_argument("--login-pass", default="", help="Password for login.")
    auth.add_argument("--login-user-field", default="",
                      help="Username form field name (auto-detected if omitted).")
    auth.add_argument("--login-pass-field", default="",
                      help="Password form field name (auto-detected if omitted).")
    auth.add_argument("--login-check", default="", metavar="STRING",
                      help="A string present only when logged in (verifies success).")
    auth.add_argument("--second-cookie", default="", metavar="'k=v'",
                      help="A second user's cookie, for confirmed cross-user IDOR testing.")

    p.add_argument("--max-urls", type=int, default=300, help="Cap harvested URLs.")
    p.add_argument("--no-crawl", action="store_true", help="Disable the active crawler.")
    p.add_argument("--crawl-depth", type=int, default=2, help="Crawler depth (default: 2).")
    p.add_argument("--crawl-pages", type=int, default=200,
                   help="Max pages to crawl (default: 200).")
    p.add_argument("--render", dest="render_mode", action="store_const", const="on",
                   default="auto",
                   help="Force headless JS rendering of seed pages (needs Playwright).")
    p.add_argument("--no-render", dest="render_mode", action="store_const", const="off",
                   help="Disable headless JS rendering (default: auto, only when SPA-like).")
    p.add_argument("--render-pages", type=int, default=5,
                   help="Max pages to render with a headless browser (default: 5).")
    p.add_argument("--no-js", action="store_true",
                   help="Disable JavaScript endpoint/secret analysis.")
    p.add_argument("--no-cve", action="store_true",
                   help="Disable version→CVE matching.")
    p.add_argument("--no-default-creds", action="store_true",
                   help="Disable default/weak-credential testing (login forms + Basic Auth).")
    p.add_argument("--no-csrf", action="store_true",
                   help="Disable anti-CSRF-token checking on POST forms.")
    p.add_argument("--no-openapi", action="store_true",
                   help="Disable OpenAPI/Swagger spec discovery and parsing.")
    p.add_argument("--timeout", type=float, default=12.0, help="Per-request timeout (s).")
    p.add_argument("--max-time", type=float, default=900.0,
                   help="Time budget for the vuln-scan phase in seconds (default: 900).")
    p.add_argument("--concurrency", type=int, default=20, help="Concurrent workers.")
    p.add_argument("--rate-limit", type=float, default=0.0,
                   help="Max requests/second for native checks (0 = unlimited).")
    p.add_argument("--stealth", action="store_true",
                   help="Polite mode: low concurrency, rate-limit, and jitter.")
    p.add_argument("--no-adaptive", action="store_true",
                   help="Disable automatic back-off when the target blocks/rate-limits.")

    p.add_argument("--doh", action="store_true", help="Force DNS-over-HTTPS resolution.")
    p.add_argument("--no-doh", action="store_true", help="Never use DoH; OS resolver only.")

    p.add_argument("-q", "--quiet", action="store_true", help="Minimal output.")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    p.add_argument("--version", action="version", version=f"strix {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
