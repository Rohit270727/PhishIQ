import re


def build_signal_breakdown(flags):
    """Split flags into scored signals (sorted highest-impact first) and informational notes (0-point)."""
    signals = [(reason, points) for reason, points in flags if points != 0]
    signals.sort(key=lambda x: x[1], reverse=True)
    notes = [(reason, points) for reason, points in flags if points == 0]
    return signals, notes


def get_primary_reason(flags):
    """Return a single plain-English sentence: the highest-weighted contributing signal."""
    scored = [(reason, points) for reason, points in flags if points != 0]
    if not scored:
        return "No significant risk indicators were found."
    top_reason, _ = max(scored, key=lambda x: x[1])
    return top_reason


def get_confidence(flags):
    """
    Derive a confidence label from the ML model's note (if present), falling back to
    heuristic signal weight otherwise.

    IMPORTANT: this is NOT a calibrated probability. predict_proba() output from an
    uncalibrated classifier is probability-shaped but not necessarily accurate at face
    value (e.g. "73%" is not provably more reliable than "71%"). This label buckets the
    raw score into High/Medium/Low based on distance from the decision boundary, and is
    marked as uncalibrated so the UI never overstates precision.
    """
    pct = None
    for reason, _points in flags:
        m = re.search(r"(\d+)%\s+(?:phishing|scam)\s+probability", reason)
        if m:
            pct = int(m.group(1))
            break

    if pct is not None:
        distance = abs(pct - 50)
        if distance >= 35:
            label = "High"
        elif distance >= 15:
            label = "Medium"
        else:
            label = "Low"
        return {"label": label, "raw_percent": pct, "source": "ml_model", "calibrated": False}

    scored_points = [points for _reason, points in flags if points > 0]
    total = sum(scored_points)
    if total >= 60:
        label = "High"
    elif total >= 30:
        label = "Medium"
    else:
        label = "Low"
    return {"label": label, "raw_percent": None, "source": "heuristic_only", "calibrated": False}
