import tldextract
from collections import defaultdict

# --- Tunable safety knobs ---
MIN_FEEDBACK_COUNT = 3      # a domain needs at least this many feedback entries before we trust it
CONSENSUS_THRESHOLD = 0.6   # at least 60% of feedback must agree on a direction
MAX_ADJUSTMENT = 15         # hard cap on how many points the adjustment can shift the score


def _registered_domain_from_url(raw_url):
    """Best-effort extraction of the registered domain (e.g. paypal-secure.tk) from a stored URL string."""
    ext = tldextract.extract(raw_url)
    if not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}".lower()


def compute_domain_feedback_map(feedback_rows):
    """
    feedback_rows: iterable of (registered_domain, feedback_type) tuples.
    Returns: dict of registered_domain -> {"correct": n, "false_positive": n, "false_negative": n, "total": n}
    """
    tally = defaultdict(lambda: {"correct": 0, "false_positive": 0, "false_negative": 0, "total": 0})
    for domain, feedback_type in feedback_rows:
        if not domain:
            continue
        tally[domain][feedback_type] += 1
        tally[domain]["total"] += 1
    return tally


def get_adjustment_for_domain(domain_tally):
    """
    Given a tally dict like {"correct": 1, "false_positive": 4, "false_negative": 0, "total": 5},
    returns (adjustment_points, reason_message) or (0, None) if no safe adjustment applies.

    Positive adjustment_points = score should go UP (community says it's more dangerous than detected).
    Negative adjustment_points = score should go DOWN (community says it's safer than detected, i.e. false positive).
    """
    total = domain_tally["total"]
    if total < MIN_FEEDBACK_COUNT:
        return 0, None

    fp_ratio = domain_tally["false_positive"] / total
    fn_ratio = domain_tally["false_negative"] / total

    if fp_ratio >= CONSENSUS_THRESHOLD:
        points = -round(min(MAX_ADJUSTMENT, fp_ratio * MAX_ADJUSTMENT / CONSENSUS_THRESHOLD))
        reason = (
            f"Community feedback: {domain_tally['false_positive']}/{total} users marked this domain "
            f"as a false positive â€” score adjusted down"
        )
        return points, reason

    if fn_ratio >= CONSENSUS_THRESHOLD:
        points = round(min(MAX_ADJUSTMENT, fn_ratio * MAX_ADJUSTMENT / CONSENSUS_THRESHOLD))
        reason = (
            f"Community feedback: {domain_tally['false_negative']}/{total} users flagged this domain "
            f"as a missed threat â€” score adjusted up"
        )
        return points, reason

    reason = (
        f"Community feedback: {total} responses on this domain, no clear consensus â€” no adjustment applied"
    )
    return 0, reason
def get_live_domain_tally():
    """
    Queries all Feedback joined to their ScanHistory row, extracts the registered domain
    for each, and returns the aggregated tally map. Uses a deferred import to avoid
    circular imports between models.py and the detectors package.
    """
    from models import Feedback, ScanHistory

    rows = (
        ScanHistory.query
        .join(Feedback, Feedback.scan_id == ScanHistory.id)
        .with_entities(ScanHistory.input_data, Feedback.feedback_type)
        .all()
    )

    domain_rows = [(_registered_domain_from_url(url), ftype) for url, ftype in rows]
    return compute_domain_feedback_map(domain_rows)
def get_domain_tally(registered_domain):
    """
    Scoped version of get_live_domain_tally() - only pulls feedback rows whose
    stored URL plausibly belongs to the given registered domain, then confirms
    with an exact tldextract match in Python. Avoids scanning the whole feedback
    table on every single scan.
    """
    empty_tally = {"correct": 0, "false_positive": 0, "false_negative": 0, "total": 0}

    if not registered_domain:
        return empty_tally

    try:
        from models import Feedback, ScanHistory

        rows = (
            ScanHistory.query
            .join(Feedback, Feedback.scan_id == ScanHistory.id)
            .filter(ScanHistory.input_data.ilike(f"%{registered_domain}%"))
            .with_entities(ScanHistory.input_data, Feedback.feedback_type)
            .all()
        )
    except Exception:
        # No app/DB context available (e.g. unit tests, standalone scripts) -
        # feedback adjustment is a best-effort enhancement, never a hard dependency.
        return empty_tally

    domain_rows = [
        (d, ftype) for url, ftype in rows
        if (d := _registered_domain_from_url(url)) == registered_domain
    ]
    tally_map = compute_domain_feedback_map(domain_rows)
    return tally_map.get(registered_domain, empty_tally)
