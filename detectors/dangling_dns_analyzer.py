"""
detectors/dangling_dns_analyzer.py
Detects subdomain takeover risk: a CNAME pointing at a known third-party
service (Heroku, GitHub Pages, S3, Azure, etc.) whose target no longer
resolves - meaning the service slot was deprovisioned and is now
claimable by anyone, who could then serve arbitrary content under a
legitimate-looking subdomain of a trusted company.
"""
import dns.resolver

_TIMEOUT = 3

# CNAME target patterns known to be commonly vulnerable to takeover when
# dangling. Deliberately a well-documented, conservative list - services
# where an unclaimed target can be freely re-registered by anyone.
_TAKEOVER_PRONE_PATTERNS = [
    ("herokuapp.com", "Heroku"),
    ("github.io", "GitHub Pages"),
    ("s3.amazonaws.com", "AWS S3"),
    ("s3-website", "AWS S3 (website hosting)"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.net", "Azure Cloud Service"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("shopify.com", "Shopify"),
    ("myshopify.com", "Shopify"),
    ("wordpress.com", "WordPress.com"),
    ("ghost.io", "Ghost"),
    ("fastly.net", "Fastly"),
    ("pantheonsite.io", "Pantheon"),
    ("surge.sh", "Surge.sh"),
    ("bitbucket.io", "Bitbucket Pages"),
    ("unbouncepages.com", "Unbounce"),
    ("zendesk.com", "Zendesk"),
    ("statuspage.io", "Statuspage"),
]


def _resolve_cname(domain: str):
    """Returns the CNAME target string, or None if there's no CNAME,
    or the sentinel 'NXDOMAIN' string if a CNAME exists but the target
    itself does not resolve (the actual dangling condition)."""
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=_TIMEOUT)
        target = str(answers[0]).strip().rstrip(".")
        return target
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        return None


def _target_resolves(target_domain: str) -> bool:
    """Returns False only on a confirmed NXDOMAIN for the target - other
    failures (timeout, temporary issues) are treated as inconclusive and
    do NOT trigger a false takeover flag, since a real dangling record
    should reliably NXDOMAIN, not just time out once."""
    try:
        dns.resolver.resolve(target_domain, "A", lifetime=_TIMEOUT)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return True  # inconclusive - assume resolves, avoid false positive


def check_dangling_dns(domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    cname_target = _resolve_cname(domain)
    if not cname_target:
        return []

    matched_service = None
    for pattern, service_name in _TAKEOVER_PRONE_PATTERNS:
        if pattern in cname_target.lower():
            matched_service = service_name
            break

    if not matched_service:
        return []

    if not _target_resolves(cname_target):
        return [(
            f"Domain has a dangling CNAME pointing to an unclaimed {matched_service} slot ({cname_target}) — possible subdomain takeover",
            35
        )]

    return []
