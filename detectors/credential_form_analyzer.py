"""
detectors/credential_form_analyzer.py
Inspects an already-loaded page's DOM for password/credential input
fields. Takes a Playwright `page` object (opened once by url_analyzer.py
via page_session.py) rather than launching its own browser per call.
"""
import re
from urllib.parse import urljoin, urlparse

_SENSITIVE_FIELD_PATTERNS = {
    "ssn": re.compile(r"ssn|social.?security", re.IGNORECASE),
    "card number": re.compile(r"card.?num|credit.?card|cc.?num", re.IGNORECASE),
    "cvv": re.compile(r"\bcvv\b|\bcvc\b|security.?code", re.IGNORECASE),
    "pin": re.compile(r"\bpin\b|\batm.?pin\b", re.IGNORECASE),
    "otp": re.compile(r"\botp\b|one.?time.?(pass|code)", re.IGNORECASE),
    "date of birth": re.compile(r"\bdob\b|date.?of.?birth|birth.?date", re.IGNORECASE),
}


def _field_signature(el_attrs: dict) -> str:
    return " ".join(
        str(el_attrs.get(k, "")) for k in ("name", "id", "placeholder", "aria-label")
    ).lower()


def check_credential_forms(page, url: str, domain: str) -> list:
    """Returns (message, points) tuples. `page` must already be loaded
    by the caller (see page_session.py). Returns [] if page is None
    (session failed to open) rather than raising."""
    if page is None:
        return []

    try:
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
    except Exception:
        return []

    out = []
    if not has_password_field and not sensitive_found:
        return out

    if has_password_field:
        out.append(("Page contains a password input field", 5))

    if sensitive_found:
        pts = min(30, len(sensitive_found) * 12)
        out.append((
            f"Form requests unusually sensitive data: {', '.join(sorted(sensitive_found))}",
            pts
        ))

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
            break

    return out
