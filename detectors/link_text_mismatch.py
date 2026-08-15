"""
detectors/link_text_mismatch.py
Flags <a> tags where the visible text looks like a domain/URL but the
actual href points somewhere else entirely — a classic phishing pattern
where the link *reads* like www.paypal.com but *goes* to evil.tk.
"""
import re
from urllib.parse import urlparse
from html.parser import HTMLParser

_DOMAIN_LIKE_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/\S*)?$"
)


class _AnchorExtractor(HTMLParser):
    """Collects (href, visible_text) pairs for every <a> tag in the body."""

    def __init__(self):
        super().__init__()
        self.anchors = []
        self._current_href = None
        self._current_text = []
        self._in_anchor = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            self._in_anchor = True
            self._current_href = href
            self._current_text = []

    def handle_data(self, data):
        if self._in_anchor:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._in_anchor:
            text = "".join(self._current_text).strip()
            self.anchors.append((self._current_href, text))
            self._in_anchor = False
            self._current_href = None
            self._current_text = []


def _extract_domain(value: str) -> str:
    """Best-effort domain extraction from either a full URL or a bare
    domain-like string (e.g. 'www.paypal.com' has no scheme)."""
    if not value:
        return ""
    candidate = value if re.match(r"^https?://", value, re.IGNORECASE) else f"http://{value}"
    netloc = urlparse(candidate).netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.split(":")[0]


def check_link_text_mismatch(html_body: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop.
    Expects raw HTML (tags intact) — pass the output of extract_html_body(),
    never pre-flattened text."""
    out = []
    if not html_body:
        return out

    parser = _AnchorExtractor()
    try:
        parser.feed(html_body)
    except Exception:
        return out

    for href, visible_text in parser.anchors:
        if not href or not visible_text:
            continue
        if not _DOMAIN_LIKE_PATTERN.match(visible_text):
            continue  # visible text isn't domain-like (e.g. "click here") — not this check's job

        visible_domain = _extract_domain(visible_text)
        href_domain = _extract_domain(href)

        if visible_domain and href_domain and visible_domain != href_domain:
            out.append((
                f"Link text displays '{visible_domain}' but actually points to '{href_domain}'",
                25
            ))

    return out
