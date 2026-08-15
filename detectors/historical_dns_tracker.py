"""
detectors/historical_dns_tracker.py
Tracks a domain's DNS footprint (A records, NS records) across scans over
time, using PhishIQ's own scan history as the data source - no third-party
historical-DNS API or key required. Flags rapid infrastructure churn
(IP or nameserver changes within a short window), which is a stronger
phishing signal than a domain's DNS slowly changing over months, since
legitimate sites rarely re-host on a different IP/registrar within days.
"""
import json
from datetime import datetime, timedelta
from detectors.dns_analyzer import analyze_dns

_RECENT_CHANGE_WINDOW_DAYS = 7


def check_historical_dns(domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop.
    Deferred import of models mirrors the pattern in feedback_adjuster.py,
    avoiding circular imports between detectors and the Flask app."""
    from models import db, DnsSnapshot

    current = analyze_dns(domain)
    current_a = sorted(current.get("a_records") or [])
    current_ns = sorted(current.get("ns_records") or [])

    flags = []

    last_snapshot = (
        DnsSnapshot.query
        .filter_by(domain=domain)
        .order_by(DnsSnapshot.recorded_at.desc())
        .first()
    )

    if last_snapshot is not None:
        prior_a = sorted(json.loads(last_snapshot.a_records or "[]"))
        prior_ns = sorted(json.loads(last_snapshot.ns_records or "[]"))
        is_recent = (
            last_snapshot.recorded_at is not None
            and datetime.utcnow() - last_snapshot.recorded_at < timedelta(days=_RECENT_CHANGE_WINDOW_DAYS)
        )

        if current_a and prior_a and current_a != prior_a and is_recent:
            flags.append((
                f"Domain's IP address changed within the last {_RECENT_CHANGE_WINDOW_DAYS} days ({', '.join(prior_a)} -> {', '.join(current_a)}) - rapid infrastructure churn",
                20
            ))

        if current_ns and prior_ns and current_ns != prior_ns and is_recent:
            flags.append((
                f"Domain's nameservers changed within the last {_RECENT_CHANGE_WINDOW_DAYS} days ({', '.join(prior_ns)} -> {', '.join(current_ns)}) - possible hosting/registrar migration",
                25
            ))

    snapshot = DnsSnapshot(
        domain=domain,
        a_records=json.dumps(current_a),
        ns_records=json.dumps(current_ns),
    )
    db.session.add(snapshot)
    db.session.commit()

    return flags
