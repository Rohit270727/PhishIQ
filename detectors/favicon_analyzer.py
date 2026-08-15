"""
detectors/favicon_analyzer.py
Fetches a site's favicon and compares its hash against known brand
favicons. Direct fetch via requests first (cheap, no browser); falls
back to reading <link rel="icon"> from an already-loaded Playwright
`page` (shared session from page_session.py) rather than launching
its own browser.
"""
import os
import json
import hashlib
import requests
import tldextract
from urllib.parse import urljoin

HASHES_PATH = os.path.join(os.path.dirname(__file__), "brand_favicon_hashes.json")

try:
    with open(HASHES_PATH, encoding="utf-8-sig") as f:
        BRAND_FAVICON_HASHES = json.load(f)
except FileNotFoundError:
    BRAND_FAVICON_HASHES = {}

_REQUEST_TIMEOUT = 6
_MAX_FAVICON_BYTES = 2 * 1024 * 1024


def _hash_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _fetch_direct(base_url: str):
    try:
        favicon_url = urljoin(base_url, "/favicon.ico")
        resp = requests.get(favicon_url, timeout=_REQUEST_TIMEOUT, stream=True)
        if resp.status_code != 200:
            return None
        content_type = resp.headers.get("Content-Type", "")
        if "image" not in content_type and "icon" not in content_type:
            return None
        data = resp.content
        if not data or len(data) > _MAX_FAVICON_BYTES:
            return None
        return data
    except requests.RequestException:
        return None


def _fetch_via_page(page):
    """Reads <link rel='icon'> from an already-loaded page instead of
    launching a separate browser session."""
    if page is None:
        return None
    try:
        icon_href = page.eval_on_selector(
            "link[rel~='icon']", "el => el.href"
        ) if page.query_selector("link[rel~='icon']") else None

        if not icon_href:
            return None

        resp = requests.get(icon_href, timeout=_REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.content
        if not data or len(data) > _MAX_FAVICON_BYTES:
            return None
        return data
    except Exception:
        return None


def _registered_domain_matches_brand(domain: str, brand: str) -> bool:
    ext = tldextract.extract(domain)
    return ext.domain.lower() == brand.lower()


def check_favicon(page, url: str, domain: str) -> list:
    """Returns (message, points) tuples. `page` is the shared session
    page (may be None if the session failed to open - direct fetch is
    tried regardless since it doesn't need a browser)."""
    if not BRAND_FAVICON_HASHES:
        return []

    favicon_bytes = _fetch_direct(url)
    if favicon_bytes is None:
        favicon_bytes = _fetch_via_page(page)
    if favicon_bytes is None:
        return []

    favicon_hash = _hash_bytes(favicon_bytes)

    for brand, known_hash in BRAND_FAVICON_HASHES.items():
        if favicon_hash == known_hash and not _registered_domain_matches_brand(domain, brand):
            return [(
                f"Page serves '{brand}' brand's exact favicon but domain does not match — possible impersonation",
                20
            )]

    return []
