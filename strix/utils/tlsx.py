"""TLS/certificate inspection.

Opens a TLS connection (without verification, so self-signed or expired certs
are still readable) and parses the presented certificate with ``cryptography``.
Separately attempts a verifying handshake to record whether the chain and
hostname actually validate — the difference is what becomes a finding later.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def _name_attr(name, oid) -> str:
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""
    except Exception:  # noqa: BLE001
        return ""


def _parse_cert(der: bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der, default_backend())
    subject_cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa: BLE001 - no SAN extension
        pass

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    now = datetime.now(timezone.utc)
    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "sans": sorted(set(sans)),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": (not_after - now).days,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "self_signed": cert.issuer == cert.subject,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "serial": format(cert.serial_number, "x"),
    }


def inspect(host: str, port: int = 443, timeout: float = 10.0, ip: str = "") -> dict[str, Any]:
    """Return a dict of TLS facts for ``host:port`` (empty on connect failure).

    ``ip`` optionally supplies a pre-resolved address to connect to, while SNI and
    validation still use ``host`` — so TLS works even where the OS DNS path is
    unreliable.
    """
    info: dict[str, Any] = {"host": host, "port": port}
    connect_host = ip or host

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["protocol"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                    info["cipher_bits"] = cipher[2]
                der = ssock.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001 - not a TLS service / unreachable
        info["error"] = str(exc)
        return info

    if der:
        try:
            info.update(_parse_cert(der))
        except Exception as exc:  # noqa: BLE001
            info["parse_error"] = str(exc)

    # Second pass: does the certificate actually validate (chain + hostname)?
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                info["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        info["trusted"] = False
        info["verify_error"] = exc.verify_message or str(exc)
    except Exception as exc:  # noqa: BLE001
        info["trusted"] = False
        info["verify_error"] = str(exc)

    return info
