"""
detectors/favicon_analyzer.py
Fetches a site's favicon and compares its hash against known brand
favicons. A domain that is not the real brand but serves the real
brand's exact favicon bytes is a strong phishing signal (attackers
copy visual assets but rarely bother regenerating icon files).
"""
import os
import json
import hashlib
import requests
import tldextract
from urllib.parse import urljoin
from playwright.sync_api import sync_playwright

HASHES_PATH = os.path.join(os.path.dirname(__file__), "brand_favicon_hashes.json")

try:
    with open(HASHES_PATH, encoding="utf-8-sig") as f:
        BRAND_FAVICON_HASHES = json.load(f)
except FileNotFoundError:
    BRAND_FAVICON_HASHES = {}

_REQUEST_TIMEOUT = 6
_MAX_FAVICON_BYTES = 2 * 1024 * 1024  # 2MB sanity cap


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


def _fetch_via_browser(base_url: str):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(base_url, timeout=10000)
            icon_href = page.eval_on_selector(
                "link[rel~='icon']", "el => el.href"
            ) if page.query_selector("link[rel~='icon']") else None
            page.close()
            browser.close()

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
    """True only if the domain's actual registrable label is the brand
    itself (paypal.com, paypal.co.uk) — NOT merely containing the brand
    name as a substring (paypal-verify-account.tk must NOT match)."""
    ext = tldextract.extract(domain)
    return ext.domain.lower() == brand.lower()


def check_favicon(url: str, domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    if not BRAND_FAVICON_HASHES:
        return []

    favicon_bytes = _fetch_direct(url)
    if favicon_bytes is None:
        favicon_bytes = _fetch_via_browser(url)
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
