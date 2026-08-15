"""
detectors/fake_captcha_analyzer.py
Detects pages that visually present CAPTCHA/human-verification UI
without actually embedding a real CAPTCHA provider (reCAPTCHA, hCaptcha,
Cloudflare Turnstile, etc). Phishing kits commonly fake this UI to
legitimize a flow or trick users into a malicious click/download, since
they can't embed a real provider (they don't control post-verification
logic). A real CAPTCHA's provider script/iframe presence is the tell
that distinguishes genuine verification from a lure.
"""
import re
from playwright.sync_api import sync_playwright

_PAGE_LOAD_TIMEOUT_MS = 10000

_CAPTCHA_LANGUAGE_PATTERN = re.compile(
    r"i'?m not a robot|verify (that )?you'?re human|human verification|"
    r"prove you'?re (not a robot|human)|security check|verify you are human|"
    r"click (the box|here) to verify|complete the verification",
    re.IGNORECASE
)

_REAL_PROVIDER_PATTERNS = [
    re.compile(r"google\.com/recaptcha", re.IGNORECASE),
    re.compile(r"gstatic\.com/recaptcha", re.IGNORECASE),
    re.compile(r"hcaptcha\.com", re.IGNORECASE),
    re.compile(r"challenges\.cloudflare\.com", re.IGNORECASE),
    re.compile(r"funcaptcha\.com|arkoselabs\.com", re.IGNORECASE),
]


def _inspect_page(url: str):
    """Returns (has_captcha_language, has_real_provider) or None on failure."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=_PAGE_LOAD_TIMEOUT_MS)
            page.wait_for_timeout(1000)

            body_text = page.inner_text("body") or ""
            has_captcha_language = bool(_CAPTCHA_LANGUAGE_PATTERN.search(body_text))

            has_real_provider = False
            sources = []
            for iframe in page.query_selector_all("iframe"):
                src = iframe.get_attribute("src")
                if src:
                    sources.append(src)
            for script in page.query_selector_all("script"):
                src = script.get_attribute("src")
                if src:
                    sources.append(src)

            for src in sources:
                if any(p.search(src) for p in _REAL_PROVIDER_PATTERNS):
                    has_real_provider = True
                    break

            page.close()
            browser.close()

        return has_captcha_language, has_real_provider
    except Exception:
        return None


def check_fake_captcha(url: str, domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    result = _inspect_page(url)
    if result is None:
        return []

    has_captcha_language, has_real_provider = result

    if has_captcha_language and not has_real_provider:
        return [(
            "Page displays human-verification/CAPTCHA language but does not load a real CAPTCHA provider — likely fake verification lure",
            22
        )]

    return []
