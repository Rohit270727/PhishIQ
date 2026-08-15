"""
detectors/link_mismatch_detector.py
Detects HTML anchor tags where visible link text names one domain but
the actual href points elsewhere. Pure parsing, stdlib only.
"""
import re
from urllib.parse import urlparse

_ANCHOR_PATTERN = re.compile(
    r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)
_TAG_STRIP = re.compile(r'<[^>]+>')
_DOMAIN_IN_TEXT = re.compile(r'\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b')


def check_link_text_mismatch(html_content: str) -> list:
    """Returns (message, points) tuples. Expects raw HTML body content."""
    out = []
    if not html_content or "<a" not in html_content.lower():
        return out

    for match in _ANCHOR_PATTERN.finditer(html_content):
        href, visible_text = match.group(1), match.group(2)
        visible_text_clean = _TAG_STRIP.sub("", visible_text).strip()

        text_domain_match = _DOMAIN_IN_TEXT.search(visible_text_clean)
        if not text_domain_match:
            continue  # link text doesn't name a domain, nothing to compare

        claimed_domain = text_domain_match.group(1).lower()
        try:
            actual_domain = urlparse(href).netloc.lower().split(":")[0]
        except Exception:
            continue

        if not actual_domain:
            continue

        if claimed_domain != actual_domain and not actual_domain.endswith("." + claimed_domain):
            out.append((
                f"Link text names '{claimed_domain}' but actually points to '{actual_domain}'",
                22
            ))

    # Cap so a message with many links can't runaway-stack
    capped = []
    total = 0
    for msg, pts in out:
        remaining = max(0, 40 - total)
        applied = min(pts, remaining)
        capped.append((msg, applied))
        total += applied
    return capped
