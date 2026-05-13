import asyncio
import ssl
import socket
from datetime import datetime, timezone


async def run_ssl_check(target: str, progress_callback=None) -> dict:
    """Check SSL/TLS certificate and cipher configuration."""
    if progress_callback:
        await progress_callback("ssl", 10, "Starting SSL/TLS check...")

    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = 443

    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            pass

    results = {
        "host": host,
        "port": port,
        "certificate": {},
        "protocols": [],
        "vulnerabilities": [],
        "grade": "unknown",
    }

    try:
        cert_info = await asyncio.get_event_loop().run_in_executor(
            None, _get_cert_info, host, port
        )
        results["certificate"] = cert_info
        if progress_callback:
            await progress_callback("ssl", 40, "Certificate retrieved, checking protocols...")
    except Exception as e:
        results["certificate"] = {"error": str(e)}
        results["vulnerabilities"].append({
            "type": "connection_failed",
            "severity": "high",
            "description": f"Could not connect to {host}:{port} — {e}",
        })
        if progress_callback:
            await progress_callback("ssl", 90, "SSL check complete (connection failed)")
        return results

    protocol_results = await asyncio.get_event_loop().run_in_executor(
        None, _check_protocols, host, port
    )
    results["protocols"] = protocol_results

    _analyze_ssl_results(results)

    if progress_callback:
        await progress_callback("ssl", 90, "SSL analysis complete...")

    return results


def _get_cert_info(host: str, port: int) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    import binascii

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            protocol = ssock.version()

    if not der_cert:
        raise ValueError(f"No certificate presented by {host}:{port}")

    cert = x509.load_der_x509_certificate(der_cert)
    now = datetime.now(timezone.utc)

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_until_expiry = (not_after - now).days
    is_expired = days_until_expiry < 0
    expiring_soon = 0 <= days_until_expiry <= 30

    # Subject / issuer
    def dn_dict(name):
        return {attr.oid._name: attr.value for attr in name}

    subject = dn_dict(cert.subject)
    issuer = dn_dict(cert.issuer)

    # SANs
    sans = []
    try:
        from cryptography.x509 import DNSName, IPAddress, RFC822Name
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for entry in san_ext.value:
            if isinstance(entry, DNSName):
                sans.append(entry.value)
            elif isinstance(entry, IPAddress):
                sans.append(str(entry.value))
            elif isinstance(entry, RFC822Name):
                sans.append(entry.value)
            else:
                sans.append(str(entry.value))
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.strftime("%b %d %H:%M:%S %Y UTC"),
        "not_after": not_after.strftime("%b %d %H:%M:%S %Y UTC"),
        "days_until_expiry": days_until_expiry,
        "is_expired": is_expired,
        "expiring_soon": expiring_soon,
        "serial_number": str(cert.serial_number),
        "subject_alt_names": sans,
        "negotiated_cipher": cipher[0] if cipher else None,
        "negotiated_protocol": protocol,
    }


def _check_protocols(host: str, port: int) -> list[dict]:
    to_test = []
    if hasattr(ssl, "TLSVersion"):
        to_test = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]

    results = []
    for name, version in to_test:
        supported = _test_tls_version(host, port, version)
        deprecated = name in ("TLSv1.0", "TLSv1.1")
        results.append({"protocol": name, "supported": supported, "deprecated": deprecated})
    return results


def _test_tls_version(host: str, port: int, version: "ssl.TLSVersion") -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _analyze_ssl_results(results: dict):
    cert = results.get("certificate", {})
    vulns = results["vulnerabilities"]

    if cert.get("is_expired"):
        vulns.append({
            "type": "expired_certificate",
            "severity": "critical",
            "description": "SSL certificate has expired",
        })
    elif cert.get("expiring_soon"):
        days = cert.get("days_until_expiry", 0)
        vulns.append({
            "type": "expiring_certificate",
            "severity": "medium",
            "description": f"SSL certificate expires in {days} days",
        })

    for proto in results.get("protocols", []):
        if proto["supported"] and proto["deprecated"]:
            vulns.append({
                "type": "deprecated_protocol",
                "severity": "high",
                "description": f"Deprecated protocol supported: {proto['protocol']}",
            })

    has_critical = any(v["severity"] == "critical" for v in vulns)
    has_high = any(v["severity"] == "high" for v in vulns)
    has_medium = any(v["severity"] == "medium" for v in vulns)

    if has_critical:
        results["grade"] = "F"
    elif has_high:
        results["grade"] = "C"
    elif has_medium:
        results["grade"] = "B"
    elif vulns:
        results["grade"] = "B+"
    else:
        results["grade"] = "A"
