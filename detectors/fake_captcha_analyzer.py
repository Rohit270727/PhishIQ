"""
detectors/fake_captcha_analyzer.py
Detects CAPTCHA-mimicking UI with no real CAPTCHA provider embedded.
Takes a Playwright `page` object rather than launching its own browser.
"""
import re

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


def check_fake_captcha(page, url: str, domain: str) -> list:
    """Returns (message, points) tuples. `page` must already be loaded
    by the caller (see page_session.py)."""
    if page is None:
        return []

    try:
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
    except Exception:
        return []

    if has_captcha_language and not has_real_provider:
        return [(
            "Page displays human-verification/CAPTCHA language but does not load a real CAPTCHA provider — likely fake verification lure",
            22
        )]

    return []
