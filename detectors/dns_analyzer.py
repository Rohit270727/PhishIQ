"""
detectors/dns_analyzer.py
DNS footprint analysis (A/AAAA/MX/NS/TXT/CNAME) — DNS-only, no API keys.
"""
import dns.resolver

_TIMEOUT = 3

_SUSPICIOUS_NS_KEYWORDS = [
    "freenom", "afraid.org", "dns-parking", "sedoparking",
    "above.com", "bodis.com",
]


def _safe_resolve(domain: str, record_type: str, timeout: int = _TIMEOUT):
    """Returns a list of string values, or None if the lookup genuinely
    failed (NXDOMAIN/NoAnswer/timeout) vs [] which we never return —
    callers should treat None as 'could not determine', not 'absent'."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=timeout)
        return [str(r).strip().rstrip(".") for r in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return None


def analyze_dns(domain: str) -> dict:
    result = {
        "domain": domain,
        "a_records": None,
        "aaaa_records": None,
        "mx_records": None,
        "ns_records": None,
        "txt_records": None,
        "cname_records": None,
        "domain_resolves": None,
        "dns_risk_score": 0,
        "risk_notes": [],
    }

    a = _safe_resolve(domain, "A")
    aaaa = _safe_resolve(domain, "AAAA")
    result["a_records"] = a
    result["aaaa_records"] = aaaa

    if a is None and aaaa is None:
        result["domain_resolves"] = False
        result["dns_risk_score"] += 30
        result["risk_notes"].append(f"Domain {domain} does not resolve (NXDOMAIN) — likely dead or never-registered infrastructure")
        # No point querying further records for a domain that doesn't exist
        return result

    result["domain_resolves"] = True
    if a == [] and aaaa == []:
        result["dns_risk_score"] += 15
        result["risk_notes"].append("Domain exists but has no A/AAAA records — cannot actually be visited directly")

    mx = _safe_resolve(domain, "MX")
    result["mx_records"] = mx
    if mx == []:
        result["risk_notes"].append("No MX records — domain cannot receive mail (informational, not inherently malicious)")

    ns = _safe_resolve(domain, "NS")
    result["ns_records"] = ns
    if ns:
        for ns_host in ns:
            for kw in _SUSPICIOUS_NS_KEYWORDS:
                if kw in ns_host.lower():
                    result["dns_risk_score"] += 15
                    result["risk_notes"].append(f"Nameserver ({ns_host}) matches a known low-cost/parking provider pattern")
                    break
    elif ns == []:
        result["dns_risk_score"] += 10
        result["risk_notes"].append("No NS records found — unusual for a registered, resolvable domain")

    txt = _safe_resolve(domain, "TXT")
    result["txt_records"] = txt

    try:
        cname_answers = dns.resolver.resolve(domain, "CNAME", lifetime=_TIMEOUT)
        result["cname_records"] = [str(r).strip().rstrip(".") for r in cname_answers]
    except Exception:
        result["cname_records"] = []

    result["dns_risk_score"] = min(result["dns_risk_score"], 40)
    return result


def check_dns(domain: str) -> list:
    """Wrapper for url_analyzer's scoring loop. Returns (message, points)
    tuples. The capped dns_risk_score is attached to only the FIRST note
    to avoid double-counting; remaining notes are informational (0 pts)."""
    result = analyze_dns(domain)
    if not result["risk_notes"]:
        return []
    out = [(result["risk_notes"][0], result["dns_risk_score"])]
    for note in result["risk_notes"][1:]:
        out.append((note, 0))
    return out
