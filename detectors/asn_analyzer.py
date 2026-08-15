"""
detectors/asn_analyzer.py
ASN / hosting-provider analysis via RDAP (no API key required).
Resolves a domain's IP, then looks up the owning network/ASN.
"""
import socket
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, HTTPLookupError, ASNRegistryError

_TIMEOUT = 5

# Providers with a well-documented reputation for lax abuse enforcement /
# routine use by phishing and malware campaigns. Deliberately short and
# conservative — this is a weak, low-weight signal, not a blocklist.
_BULLETPROOF_ASN_KEYWORDS = [
    "stark industries", "media land", "aeza", "psychz", "hostkey",
    "flyservers", "silverstar", "king servers",
]


def _resolve_ip(domain: str, timeout: int = _TIMEOUT):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except Exception:
        return None


def analyze_asn(domain: str) -> dict:
    result = {
        "domain": domain,
        "ip": None,
        "asn": None,
        "asn_description": None,
        "network_name": None,
        "country": None,
        "checked": True,
        "asn_risk_score": 0,
        "risk_notes": [],
    }

    ip = _resolve_ip(domain)
    result["ip"] = ip
    if ip is None:
        result["checked"] = False
        result["risk_notes"].append("Could not resolve an IP for this domain to perform ASN lookup")
        return result

    try:
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)
    except IPDefinedError:
        result["checked"] = False
        result["risk_notes"].append("IP is in a private/reserved range — ASN lookup not applicable")
        return result
    except (HTTPLookupError, ASNRegistryError, Exception) as e:
        result["checked"] = False
        result["risk_notes"].append(f"ASN/RDAP lookup failed: {e}")
        return result

    result["asn"] = rdap.get("asn")
    result["asn_description"] = rdap.get("asn_description")
    result["network_name"] = (rdap.get("network") or {}).get("name")
    result["country"] = rdap.get("asn_country_code")

    desc_lower = (result["asn_description"] or "").lower()
    net_lower = (result["network_name"] or "").lower()
    for kw in _BULLETPROOF_ASN_KEYWORDS:
        if kw in desc_lower or kw in net_lower:
            result["asn_risk_score"] += 20
            result["risk_notes"].append(
                f"Hosted on a network ({result['asn_description']}) with a known history of abuse-tolerant hosting"
            )
            break

    if not result["asn_description"]:
        result["risk_notes"].append("ASN lookup succeeded but returned no organization name — unusual")

    result["asn_risk_score"] = min(result["asn_risk_score"], 20)
    return result


def check_asn(domain: str) -> list:
    """Wrapper for url_analyzer's scoring loop. Returns (message, points)."""
    result = analyze_asn(domain)
    if not result["risk_notes"]:
        return []
    out = [(result["risk_notes"][0], result["asn_risk_score"])]
    for note in result["risk_notes"][1:]:
        out.append((note, 0))
    return out
