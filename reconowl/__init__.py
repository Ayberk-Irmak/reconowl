"""reconowl — a recon-to-report offensive security orchestrator for authorized
penetration testing.

reconowl takes a single target (domain, URL, or IP) and runs a full pipeline:

1. **Passive recon** — DNS, RDAP/WHOIS, certificate-transparency subdomains,
   archived-URL harvesting. No packets to the target.
2. **Active recon** — port/service discovery (native + nmap), HTTP probing,
   TLS/certificate inspection, security-header and content discovery.
3. **Vulnerability scanning** — native checks (headers, cookies, TLS, exposed
   files, injection probes) plus orchestrated nuclei/sqlmap when available.
4. **Reporting** — a normalized findings model rendered to HTML, JSON, and
   Markdown.

The design principle: orchestrate proven engines where they exist and fall back
to reliable native checks where they do not, so results are real either way.
"""

from __future__ import annotations

__version__ = "0.3.1"
__tool__ = "reconowl"
