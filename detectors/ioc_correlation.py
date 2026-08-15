"""
detectors/ioc_correlation.py
Cross-scan IOC (indicator-of-compromise) correlation: flags when a
domain shares infrastructure (IP address or ASN) with other domains
PhishIQ has previously scanned. Sourced entirely from PhishIQ's own
scan history via IocRecord - no external threat-intel API required.

Shared hosting is common and often meaningless (CDNs, cloud platforms),
so this module deliberately limits noise two ways:
  - ASN-level correlation skips major cloud/CDN providers entirely.
  - Severity is boosted when a correlated domain's most recent scan
    verdict was actually dangerous, since infra shared with a confirmed
    bad domain is a much stronger signal than infra shared with an
    unknown one.
"""
from datetime import datetime, timedelta
from detectors.dns_analyzer import analyze_dns
from detectors.asn_analyzer import analyze_asn

_LOOKBACK_DAYS = 90

# ASNs/orgs common enough that shared-ASN alone is not meaningful signal.
_NOISY_ASN_KEYWORDS = [
    "amazon", "aws", "cloudflare", "google", "microsoft", "azure",
    "digitalocean", "akamai", "fastly", "ovh", "godaddy", "namecheap",
    "linode", "hetzner",
]


def _is_noisy_asn(asn_description):
    if not asn_description:
        return False
    desc_lower = asn_description.lower()
    return any(kw in desc_lower for kw in _NOISY_ASN_KEYWORDS)


def check_ioc_correlation(domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop.
    Deferred import of models mirrors feedback_adjuster.py and
    historical_dns_tracker.py, avoiding circular imports."""
    from models import db, IocRecord, ScanHistory

    dns_result = analyze_dns(domain)
    ip = (dns_result.get("a_records") or [None])[0]

    asn_result = analyze_asn(domain)
    asn = asn_result.get("asn")
    asn_description = asn_result.get("asn_description")

    flags = []
    cutoff = datetime.utcnow() - timedelta(days=_LOOKBACK_DAYS)

    if ip:
        ip_matches = (
            IocRecord.query
            .filter(IocRecord.ip == ip)
            .filter(IocRecord.domain != domain)
            .filter(IocRecord.recorded_at >= cutoff)
            .all()
        )
        matched_domains = sorted({m.domain for m in ip_matches})
        if matched_domains:
            points = 10
            dangerous_overlap = []
            for other_domain in matched_domains:
                last_scan = (
                    ScanHistory.query
                    .filter(ScanHistory.input_data.like(f"%{other_domain}%"))
                    .order_by(ScanHistory.created_at.desc())
                    .first()
                )
                if last_scan and last_scan.verdict and last_scan.verdict.lower() == "dangerous":
                    dangerous_overlap.append(other_domain)
            if dangerous_overlap:
                points = 30
                flags.append((
                    f"Shares an IP address ({ip}) with domain(s) previously flagged dangerous: {', '.join(dangerous_overlap)}",
                    points
                ))
            else:
                flags.append((
                    f"Shares an IP address ({ip}) with {len(matched_domains)} other previously-scanned domain(s): {', '.join(matched_domains[:5])}",
                    points
                ))

    if asn and not _is_noisy_asn(asn_description):
        asn_matches = (
            IocRecord.query
            .filter(IocRecord.asn == asn)
            .filter(IocRecord.domain != domain)
            .filter(IocRecord.recorded_at >= cutoff)
            .all()
        )
        matched_domains = sorted({m.domain for m in asn_matches})
        if matched_domains:
            flags.append((
                f"Shares an unusual hosting network ({asn_description or asn}) with {len(matched_domains)} other previously-scanned domain(s): {', '.join(matched_domains[:5])}",
                15
            ))

    record = IocRecord(domain=domain, ip=ip, asn=asn, asn_description=asn_description)
    db.session.add(record)
    db.session.commit()

    return flags


def get_correlation_graph(domain: str) -> dict:
    """Builds simple node/edge data for the IOC correlation graph on the
    result page. Returns {"nodes": [...], "edges": [...]} where each node
    has id/label/kind (center|domain|ip|asn) and kind drives SVG color in
    the template. Center node is the scanned domain; edges connect it to
    any IP/ASN it shares with previously-scanned domains, and those other
    domains hang off the shared IP/ASN node."""
    from models import IocRecord, ScanHistory

    center = {"id": domain, "label": domain, "kind": "center"}
    nodes = {domain: center}
    edges = []

    own_records = IocRecord.query.filter_by(domain=domain).order_by(IocRecord.recorded_at.desc()).all()
    if not own_records:
        return {"nodes": [center], "edges": []}

    seen_ips = {r.ip for r in own_records if r.ip}
    seen_asns = {r.asn for r in own_records if r.asn}

    for ip in seen_ips:
        ip_node_id = f"ip:{ip}"
        nodes[ip_node_id] = {"id": ip_node_id, "label": ip, "kind": "ip"}
        edges.append({"source": domain, "target": ip_node_id})

        others = (
            IocRecord.query
            .filter(IocRecord.ip == ip, IocRecord.domain != domain)
            .all()
        )
        for rec in others:
            other_id = rec.domain
            if other_id not in nodes:
                last_scan = (
                    ScanHistory.query
                    .filter(ScanHistory.input_data.like(f"%{other_id}%"))
                    .order_by(ScanHistory.created_at.desc())
                    .first()
                )
                is_dangerous = bool(last_scan and last_scan.verdict and last_scan.verdict.lower() == "dangerous")
                nodes[other_id] = {
                    "id": other_id,
                    "label": other_id,
                    "kind": "dangerous_domain" if is_dangerous else "domain",
                }
            edges.append({"source": ip_node_id, "target": other_id})

    for asn in seen_asns:
        asn_node_id = f"asn:{asn}"
        rec_with_desc = next((r for r in own_records if r.asn == asn), None)
        asn_label = rec_with_desc.asn_description if rec_with_desc and rec_with_desc.asn_description else asn
        nodes[asn_node_id] = {"id": asn_node_id, "label": asn_label, "kind": "asn"}
        edges.append({"source": domain, "target": asn_node_id})

    return {"nodes": list(nodes.values()), "edges": edges}
