"""Run configuration: scope, intensity, timeouts, and which phases run."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    """All knobs for a single scan run, assembled by the CLI."""

    target: str = ""

    # Phase toggles
    passive: bool = True
    active: bool = True
    vuln: bool = True

    # Authorization — an offensive tool must be gated on explicit consent.
    authorized: bool = False

    # Intensity / scope
    #: "light" | "normal" | "aggressive" — affects port ranges, wordlists, nuclei.
    intensity: str = "normal"
    #: Also scan discovered subdomains (can be slow/broad).
    include_subdomains: bool = False
    max_subdomains: int = 25
    #: Cap on discovered URLs pulled from archives.
    max_urls: int = 300

    # Active crawling
    crawl: bool = True
    crawl_depth: int = 2
    crawl_max_pages: int = 200
    #: Headless JS rendering for SPAs: "auto" (only when SPA-like), "on", or "off".
    render_mode: str = "auto"
    #: Max pages to render with a headless browser (cost control).
    render_max_pages: int = 5
    #: Fetch and analyze JavaScript for endpoints and secrets.
    js_analysis: bool = True
    #: Map detected software versions to known CVEs (offline database).
    cve_lookup: bool = True
    #: Try a small set of default/weak credentials against login forms + Basic Auth.
    default_creds: bool = True
    #: Flag state-changing POST forms that carry no anti-CSRF token.
    csrf_check: bool = True
    #: Discover & parse OpenAPI/Swagger specs, feeding operations to injection checks.
    openapi: bool = True

    # Networking
    timeout: float = 12.0
    concurrency: int = 20
    #: Hard time budget for the vulnerability-scan phase (seconds).
    max_scan_seconds: float = 900.0
    #: Global requests/second ceiling for native HTTP checks (politeness).
    rate_limit: float = 0.0  # 0 = unlimited
    #: Random per-request delay up to this many seconds (stealth).
    jitter: float = 0.0
    #: Automatically back off when the target starts blocking/rate-limiting.
    adaptive: bool = True
    user_agent: str = "strix/0.1 (+https://github.com/)"

    # Authentication — sent on every request so checks run authenticated.
    #: Extra request headers, e.g. {"Authorization": "Bearer ..."}.
    extra_headers: dict[str, str] = field(default_factory=dict)
    #: Cookie header value, e.g. "session=abc; role=admin".
    cookie: str = ""

    # Automated form login (captures a session used for crawl + scan).
    login_url: str = ""
    login_user: str = ""
    login_pass: str = ""
    login_user_field: str = ""   # auto-detected if empty
    login_pass_field: str = ""   # auto-detected if empty
    #: A string that appears only when logged in (verifies success).
    login_check: str = ""
    #: A second user's cookie, enabling confirmed cross-user IDOR testing.
    second_cookie: str = ""

    def has_login(self) -> bool:
        return bool(self.login_url and self.login_user)

    def build_headers(self) -> dict[str, str]:
        """Assemble the auth headers (extra headers plus any cookie)."""
        headers = dict(self.extra_headers)
        if self.cookie:
            headers["Cookie"] = self.cookie
        return headers

    def is_authenticated(self) -> bool:
        return bool(self.extra_headers or self.cookie)

    # External-tool usage
    use_external: bool = True
    #: Run nuclei (can be heavy). Respects intensity for template severity.
    run_nuclei: bool = True
    #: Run sqlmap to confirm injection candidates (slow; explicit).
    run_sqlmap: bool = False
    nuclei_extra: list[str] = field(default_factory=list)
    nmap_extra: list[str] = field(default_factory=list)

    # Directory brute-force
    dirbrute: bool = True
    #: Custom wordlist path (empty = built-in).
    wordlist: str = ""

    # SSRF out-of-band confirmation
    ssrf_oob: bool = True
    #: Reachable host the target should call back to (auto-detected if empty).
    oob_host: str = ""
    #: Listener port (0 = ephemeral).
    oob_port: int = 0

    # Output
    output_dir: str = "strix-report"
    formats: list[str] = field(default_factory=lambda: ["html", "json", "md"])
    quiet: bool = False
    no_color: bool = False

    # Port scanning
    def port_spec(self) -> str:
        """nmap-style port spec derived from intensity."""
        return {
            "light": "--top-ports 100",
            "normal": "--top-ports 1000",
            "aggressive": "-p-",
        }.get(self.intensity, "--top-ports 1000")

    def native_ports(self) -> list[int]:
        """Ports for the built-in scanner when nmap is unavailable."""
        common = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
            587, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 2375, 2376,
            3000, 3306, 3389, 5432, 5601, 5900, 5985, 6379, 7001, 8000, 8008,
            8080, 8081, 8443, 8888, 9000, 9200, 9300, 10000, 11211, 27017,
        ]
        if self.intensity == "aggressive":
            return list(range(1, 1025)) + common
        return common

    def nuclei_severity(self) -> str:
        return {
            "light": "medium,high,critical",
            "normal": "low,medium,high,critical",
            "aggressive": "info,low,medium,high,critical",
        }.get(self.intensity, "low,medium,high,critical")
