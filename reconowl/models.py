"""Core data model shared across every phase.

Everything a phase discovers becomes either an :class:`Asset` (something that
exists — a host, port, URL, subdomain) or a :class:`Finding` (something that may
be wrong). Reports are rendered purely from a :class:`ScanResult`, so phases
never touch output formatting.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity. Ordered so results sort high-to-low naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse a severity name (as used by nuclei/others), defaulting to INFO."""
        try:
            return cls[value.strip().upper()]
        except (KeyError, AttributeError):
            return cls.INFO


@dataclass
class Finding:
    """A single potential issue, from any check or orchestrated tool."""

    title: str
    severity: Severity
    target: str
    #: Short machine slug for the finding class, e.g. "missing-hsts".
    category: str = "misc"
    description: str = ""
    #: What the operator should do about it.
    remediation: str = ""
    #: Where it was found (URL, host:port, file path).
    location: str = ""
    #: Concrete supporting detail (matched string, header value, payload...).
    evidence: str = ""
    #: Which check/tool produced it, e.g. "native:headers", "nuclei".
    source: str = "reconowl"
    #: Optional references (CVE links, docs).
    references: list[str] = field(default_factory=list)
    #: Extra structured data for the JSON report.
    extra: dict[str, Any] = field(default_factory=dict)
    #: CVSS v3.1 base score / rating / vector (filled in by scoring).
    cvss_score: float | None = None
    cvss_severity: str = ""
    cvss_vector: str = ""
    #: Request/response proof: {"request": str, "response": str}.
    proof: dict[str, str] = field(default_factory=dict)

    def dedup_key(self) -> tuple[str, str, str]:
        """Findings equal on (category, location, title) are duplicates."""
        return (self.category, self.location or self.target, self.title)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass
class Port:
    """An open port with optional service/version detail."""

    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WebEndpoint:
    """A probed HTTP(S) endpoint."""

    url: str
    status: int | None = None
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int | None = None
    technologies: list[str] = field(default_factory=list)
    redirect: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Form:
    """An HTML form discovered while crawling — a POST/GET injection surface."""

    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Target:
    """The subject of a scan, parsed from user input."""

    raw: str
    #: Hostname or IP without scheme/path.
    host: str = ""
    #: Full base URL if the target is (or resolves to) a web target.
    base_url: str = ""
    ip: str = ""
    is_ip: bool = False
    scheme: str = "https"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """The single object every report is rendered from."""

    target: Target
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str = ""

    # Recon assets
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    whois: dict[str, Any] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    endpoints: list[WebEndpoint] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    #: Secret hits from JS analysis: {type, match, severity, location}.
    secrets: list[dict[str, Any]] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    waf: str = ""

    # Findings
    findings: list[Finding] = field(default_factory=list)

    # Bookkeeping
    tools_used: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(Severity)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (int(f.severity), f.cvss_score or 0.0),
            reverse=True,
        )

    def max_cvss(self) -> float:
        return max((f.cvss_score or 0.0 for f in self.findings), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "reconowl",
            "target": self.target.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "severity_counts": self.severity_counts(),
                "max_cvss": self.max_cvss(),
                "total_findings": len(self.findings),
                "open_ports": len(self.ports),
                "subdomains": len(self.subdomains),
                "endpoints": len(self.endpoints),
                "urls": len(self.urls),
            },
            "dns_records": self.dns_records,
            "whois": self.whois,
            "subdomains": self.subdomains,
            "ports": [p.to_dict() for p in self.ports],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "urls": self.urls,
            "forms": [f.to_dict() for f in self.forms],
            "js_files": self.js_files,
            "tls": self.tls,
            "technologies": self.technologies,
            "waf": self.waf,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "tools_used": self.tools_used,
            "errors": self.errors,
        }
