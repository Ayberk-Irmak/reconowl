"""Native check: risky internet-exposed services.

Turns the port/service data from active recon into findings: databases, remote-
access, and management services that should not face the internet are reported
with a severity that reflects their risk, plus admin panels fingerprinted on the
probed web endpoints. Reads already-gathered assets, so it makes no new requests.
"""

from __future__ import annotations

from ..models import Finding, ScanResult, Severity

_SOURCE = "native:exposed-service"

# port -> (service label, severity, note)
_PORT_RISK: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.MEDIUM, "Plaintext file transfer; check anonymous login and move to SFTP/FTPS."),
    23: ("Telnet", Severity.HIGH, "Plaintext remote shell; disable and use SSH."),
    69: ("TFTP", Severity.MEDIUM, "Unauthenticated file transfer exposed."),
    111: ("RPCbind", Severity.MEDIUM, "RPC portmapper exposed."),
    135: ("MSRPC", Severity.MEDIUM, "Windows RPC endpoint mapper exposed."),
    139: ("NetBIOS", Severity.HIGH, "NetBIOS session service exposed."),
    445: ("SMB", Severity.HIGH, "SMB/file sharing exposed to the internet (ransomware/EternalBlue risk)."),
    512: ("rexec", Severity.HIGH, "Legacy remote exec exposed."),
    513: ("rlogin", Severity.HIGH, "Legacy remote login exposed."),
    514: ("rsh", Severity.HIGH, "Legacy remote shell exposed."),
    161: ("SNMP", Severity.MEDIUM, "SNMP exposed; check default community strings."),
    389: ("LDAP", Severity.MEDIUM, "Directory service exposed."),
    636: ("LDAPS", Severity.LOW, "Directory service exposed."),
    1433: ("Microsoft SQL Server", Severity.HIGH, "Database exposed to the internet; restrict to localhost/VPN."),
    1521: ("Oracle Database", Severity.HIGH, "Database exposed to the internet; restrict to localhost/VPN."),
    2049: ("NFS", Severity.HIGH, "Network file share exposed."),
    2082: ("cPanel", Severity.MEDIUM, "Hosting control panel exposed; restrict access."),
    2083: ("cPanel (SSL)", Severity.MEDIUM, "Hosting control panel exposed; restrict access."),
    2086: ("WHM", Severity.MEDIUM, "Hosting control panel exposed; restrict access."),
    2087: ("WHM (SSL)", Severity.MEDIUM, "Hosting control panel exposed; restrict access."),
    2375: ("Docker API", Severity.CRITICAL, "Unauthenticated Docker API allows remote code execution."),
    2376: ("Docker API (TLS)", Severity.HIGH, "Docker API exposed."),
    3306: ("MySQL/MariaDB", Severity.HIGH, "Database exposed to the internet; restrict to localhost/VPN."),
    3389: ("RDP", Severity.HIGH, "Remote Desktop exposed (brute-force/BlueKeep); restrict via VPN."),
    4444: ("Metasploit/handler", Severity.MEDIUM, "Suspicious service port exposed."),
    5432: ("PostgreSQL", Severity.HIGH, "Database exposed to the internet; restrict to localhost/VPN."),
    5900: ("VNC", Severity.HIGH, "Remote desktop (often weak/no auth) exposed."),
    5984: ("CouchDB", Severity.HIGH, "CouchDB exposed; often unauthenticated."),
    5985: ("WinRM (HTTP)", Severity.HIGH, "Windows Remote Management exposed."),
    5986: ("WinRM (HTTPS)", Severity.MEDIUM, "Windows Remote Management exposed."),
    6379: ("Redis", Severity.HIGH, "Redis is unauthenticated by default; exposure can mean data theft/RCE."),
    7001: ("WebLogic", Severity.HIGH, "Application server admin exposed."),
    9042: ("Cassandra", Severity.HIGH, "Cassandra database exposed."),
    9200: ("Elasticsearch", Severity.HIGH, "Elasticsearch often exposes data without authentication."),
    9300: ("Elasticsearch (transport)", Severity.HIGH, "Elasticsearch cluster port exposed."),
    10000: ("Webmin", Severity.MEDIUM, "Webmin admin panel exposed."),
    11211: ("Memcached", Severity.HIGH, "Memcached exposed (data leak / DDoS amplification)."),
    27017: ("MongoDB", Severity.HIGH, "MongoDB exposed; historically unauthenticated by default."),
    27018: ("MongoDB (shard)", Severity.HIGH, "MongoDB exposed."),
    22: ("SSH", Severity.INFO, "SSH exposed (normal); ensure key-based auth and no weak credentials."),
    25: ("SMTP", Severity.INFO, "Mail service exposed; ensure it is not an open relay."),
    53: ("DNS", Severity.INFO, "DNS exposed; ensure recursion/zone-transfer are restricted."),
}

# nmap service-name -> port-table key, so risky services on non-standard ports
# are still caught.
_SERVICE_ALIASES = {
    "ftp": 21, "telnet": 23, "microsoft-ds": 445, "netbios-ssn": 139,
    "ms-sql-s": 1433, "ms-wbt-server": 3389, "mysql": 3306, "postgresql": 5432,
    "vnc": 5900, "redis": 6379, "mongodb": 27017, "elasticsearch": 9200,
    "memcached": 11211, "oracle-tns": 1521, "rdp": 3389, "smb": 445,
}

# Admin-panel fingerprints in a web endpoint's title/server/technologies.
_PANEL_SIGS = {
    "plesk": "Plesk control panel",
    "cpanel": "cPanel",
    "webmin": "Webmin",
    "phpmyadmin": "phpMyAdmin",
    "adminer": "Adminer",
    "grafana": "Grafana",
    "kibana": "Kibana",
    "jenkins": "Jenkins",
    "portainer": "Portainer",
}


def classify_port(number: int, service: str = "") -> tuple[str, Severity, str] | None:
    """Return (label, severity, note) if this port/service is risky to expose."""
    if number in _PORT_RISK:
        return _PORT_RISK[number]
    key = _SERVICE_ALIASES.get(service.lower().strip())
    if key is not None:
        return _PORT_RISK.get(key)
    return None


def _panel_findings(result: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    for ep in result.endpoints:
        haystack = " ".join([ep.title, ep.server, " ".join(ep.technologies)]).lower()
        for sig, label in _PANEL_SIGS.items():
            if sig in haystack:
                findings.append(
                    Finding(
                        title=f"Exposed admin panel: {label}",
                        severity=Severity.MEDIUM,
                        target=result.target.host,
                        category="exposed-panel",
                        location=ep.url,
                        description=f"A {label} management interface is reachable at "
                        f"{ep.url}. Admin panels should not be exposed to the internet.",
                        remediation="Restrict the panel to trusted IPs/VPN and enforce "
                        "strong authentication and MFA.",
                        evidence=(ep.title or ep.server)[:120],
                        source=_SOURCE,
                    )
                )
                break
    return findings


def check(result: ScanResult, config, client, ui) -> list[Finding]:
    findings: list[Finding] = []
    for port in result.ports:
        risk = classify_port(port.number, port.service)
        if risk is None:
            continue
        label, severity, note = risk
        version = " ".join(x for x in (port.product, port.version) if x).strip()
        findings.append(
            Finding(
                title=f"Exposed service: {label} ({port.number}/{port.protocol})",
                severity=severity,
                target=result.target.host,
                category="exposed-service",
                location=f"{result.target.host}:{port.number}",
                description=f"{label} is reachable on port {port.number}. {note}",
                remediation="Restrict the service to trusted networks (firewall/VPN) or "
                "bind it to localhost if internet exposure is not required.",
                evidence=version or f"{port.service or label} on {port.number}",
                source=_SOURCE,
                extra={"port": port.number, "service": port.service or label},
            )
        )
    findings.extend(_panel_findings(result))
    return findings
