"""
detectors/query_param_analyzer.py
Analyzes URL query parameters for open-redirect and payload-encoding patterns.
Pure parsing — no network calls, no dependencies beyond stdlib.
"""
import re
import base64
from urllib.parse import parse_qs, urlparse

_REDIRECT_PARAM_NAMES = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnurl", "return_url", "dest", "destination", "continue",
    "redir", "u", "target", "rurl", "goto", "out", "forward",
]

_URL_LIKE_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


def _looks_base64(value: str) -> bool:
    """Heuristic: reasonably long, base64-alphabet string that actually decodes."""
    if len(value) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        return False
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=False)
        decoded.decode("utf-8")
        return True
    except Exception:
        return False


def analyze_query_params(raw_url: str, own_domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    out = []
    try:
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query)
    except Exception:
        return out

    if not params:
        return out

    own_domain_lower = (own_domain or "").lower().split(":")[0]

    for key, values in params.items():
        key_lower = key.lower()
        for value in values:
            if key_lower in _REDIRECT_PARAM_NAMES and _URL_LIKE_PATTERN.match(value):
                target_domain = urlparse(value).netloc.lower().split(":")[0]
                if target_domain and target_domain != own_domain_lower:
                    out.append((
                        f"URL parameter '{key}' redirects to a different domain ({target_domain})",
                        18
                    ))
                    continue

            if _looks_base64(value):
                out.append((
                    f"URL parameter '{key}' contains a base64-encoded payload — possible obfuscation",
                    10
                ))

    # Cap total contribution from this check so one URL with many params
    # can't runaway-stack points
    capped = []
    total = 0
    for msg, pts in out:
        remaining = max(0, 30 - total)
        applied = min(pts, remaining)
        capped.append((msg, applied))
        total += applied
    return capped
