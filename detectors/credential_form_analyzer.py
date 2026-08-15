"""
detectors/credential_form_analyzer.py
Inspects a page's rendered DOM for password/credential input fields and
scores based on how aggressive the data-collection pattern looks:
a single password field is normal on any login page; multiple sensitive
fields (SSN, card number, CVV, PIN) stacked together, or a form action
pointing to a completely different domain than the page itself, are
much stronger phishing/harvesting signals.
"""
import re
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

_SENSITIVE_FIELD_PATTERNS = {
    "ssn": re.compile(r"ssn|social.?security", re.IGNORECASE),
    "card number": re.compile(r"card.?num|credit.?card|cc.?num", re.IGNORECASE),
    "cvv": re.compile(r"\bcvv\b|\bcvc\b|security.?code", re.IGNORECASE),
    "pin": re.compile(r"\bpin\b|\batm.?pin\b", re.IGNORECASE),
    "otp": re.compile(r"\botp\b|one.?time.?(pass|code)", re.IGNORECASE),
    "date of birth": re.compile(r"\bdob\b|date.?of.?birth|birth.?date", re.IGNORECASE),
}

_PAGE_LOAD_TIMEOUT_MS = 10000

# KNOWN LIMITATION: sites with bot/CAPTCHA detection (e.g. paypal.com/signin)
# will often serve headless Chromium a CAPTCHA interstitial instead of the
# real form, causing this to under-report (no password field found, even
# though the real page has one). This is a false-negative risk on well-
# protected legitimate sites, not on phishing sites, which almost never
# bother with bot detection. Verified against local static fixtures instead
# - see test_pages/. Confirmed 2026-08-15.


def _field_signature(el_attrs: dict) -> str:
    """Concatenate the attributes most likely to reveal field intent."""
    return " ".join(
        str(el_attrs.get(k, "")) for k in ("name", "id", "placeholder", "aria-label")
    ).lower()


def _inspect_page(url: str):
    """Returns (has_password_field, sensitive_fields_found set, form_actions list)
    or None on any failure — caller treats None as 'inconclusive, skip'."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=_PAGE_LOAD_TIMEOUT_MS)
            page.wait_for_timeout(1000)

            has_password_field = page.query_selector("input[type='password']") is not None

            all_inputs = page.query_selector_all("input, textarea")
            sensitive_found = set()
            for el in all_inputs:
                attrs = {
                    "name": el.get_attribute("name"),
                    "id": el.get_attribute("id"),
                    "placeholder": el.get_attribute("placeholder"),
                    "aria-label": el.get_attribute("aria-label"),
                }
                sig = _field_signature(attrs)
                for label, pattern in _SENSITIVE_FIELD_PATTERNS.items():
                    if pattern.search(sig):
                        sensitive_found.add(label)

            form_actions = []
            forms = page.query_selector_all("form")
            for form in forms:
                action = form.get_attribute("action")
                if action:
                    form_actions.append(action)

            page.close()
            browser.close()

        return has_password_field, sensitive_found, form_actions
    except Exception:
        return None


def check_credential_forms(url: str, domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    result = _inspect_page(url)
    if result is None:
        return []

    has_password_field, sensitive_found, form_actions = result
    out = []

    if not has_password_field and not sensitive_found:
        return out

    # Password field alone is normal for any legitimate login page —
    # only worth a small base signal on its own.
    if has_password_field:
        out.append(("Page contains a password input field", 5))

    # Stacking multiple sensitive field types beyond just password is
    # unusual for a normal login and typical of a harvesting form.
    if sensitive_found:
        pts = min(30, len(sensitive_found) * 12)
        out.append((
            f"Form requests unusually sensitive data: {', '.join(sorted(sensitive_found))}",
            pts
        ))

    # Form action pointing to a different domain is a strong exfil signal
    # regardless of how many fields are present.
    own_registered = domain.split(":")[0]
    for action in form_actions:
        try:
            action_domain = urlparse(urljoin(url, action)).netloc.lower().split(":")[0]
        except Exception:
            continue
        if action_domain and action_domain != own_registered and not action_domain.endswith("." + own_registered):
            out.append((
                f"Form submits data to a different domain ({action_domain}) than the page itself",
                25
            ))
            break  # one flag is enough even if multiple forms do this

    return out
