import ssl
import socket
import datetime

def inspect_certificate(domain, timeout=4):
    host = domain.split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        age_days = (datetime.datetime.utcnow() - not_before).days

        free_ca_indicators = ["let's encrypt", "zerossl", "cloudflare"]
        is_free_ca = any(ind in issuer_name.lower() for ind in free_ca_indicators)

        return {
            "valid": True,
            "issuer": issuer_name,
            "cert_age_days": age_days,
            "is_free_ca": is_free_ca
        }
    except Exception:
        return {"valid": False, "issuer": None, "cert_age_days": None, "is_free_ca": False}
