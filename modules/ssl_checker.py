# modules/ssl_checker.py
import socket
import ssl
from datetime import datetime, timezone


def check_ssl(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    context = ssl.create_default_context()
    result = {
        "hostname": hostname,
        "port": port,
        "valid": False,
        "tls_version": None,
        "cipher": None,
        "issuer": None,
        "subject": None,
        "expires_at": None,
        "days_until_expiry": None,
        "error": None,
    }

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True
                result["tls_version"] = ssock.version()
                result["cipher"] = ssock.cipher()[0]

                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
                result["subject"] = subject_dict.get("commonName")

                not_after_str = cert.get("notAfter")
                if not_after_str:
                    expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    result["expires_at"] = expires_at.isoformat()
                    result["days_until_expiry"] = (expires_at - now).days

    except Exception as e:
        result["error"] = str(e)

    return result