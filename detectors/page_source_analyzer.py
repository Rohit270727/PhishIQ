"""
detectors/page_source_analyzer.py
Inspects a page's rendered DOM for two distinct exfiltration/payload
patterns not covered by credential_form_analyzer.py:
  1. Hidden iframes (display:none, zero-size, off-screen) - often used
     to silently load malicious content or run clickjacking overlays.
  2. External resource references (script src, fetch/XHR targets in
     inline scripts) pointing to a different domain than the page -
     possible data exfiltration or injected payload.
Deliberately does NOT check <form action> - that's already handled by
credential_form_analyzer.py; duplicating it here would double-count.
"""
import re
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

_PAGE_LOAD_TIMEOUT_MS = 10000

# Matches absolute URLs inside fetch(...)/XMLHttpRequest.open(...) calls
# in inline <script> content - deliberately simple, not a JS parser.
_FETCH_XHR_PATTERN = re.compile(
    r"""(?:fetch\s*\(\s*|\.open\s*\(\s*['"]\w+['"]\s*,\s*)['"](https?://[^'"]+)['"]""",
    re.IGNORECASE
)


def _is_hidden(el) -> bool:
    """Heuristic visibility check via computed style + explicit attrs."""
    try:
        style = el.evaluate(
            "el => { const s = getComputedStyle(el); return s.display + '|' + s.visibility + '|' + s.width + '|' + s.height; }"
        )
        display, visibility, width, height = (style.split("|") + ["", "", "", ""])[:4]
        if display == "none" or visibility == "hidden":
            return True
        if width in ("0px", "0") or height in ("0px", "0"):
            return True
    except Exception:
        pass

    for attr in ("width", "height"):
        val = el.get_attribute(attr)
        if val is not None and val.strip() in ("0", "0px"):
            return True

    return False


def _inspect_page(url: str):
    """Returns (hidden_iframe_domains set, external_script_domains set)
    or None on failure - caller treats None as inconclusive, skip."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=_PAGE_LOAD_TIMEOUT_MS)
            page.wait_for_timeout(1000)

            hidden_iframe_domains = set()
            for iframe in page.query_selector_all("iframe"):
                src = iframe.get_attribute("src")
                if not src:
                    continue
                if _is_hidden(iframe):
                    try:
                        iframe_domain = urlparse(urljoin(url, src)).netloc.lower().split(":")[0]
                        if iframe_domain:
                            hidden_iframe_domains.add(iframe_domain)
                    except Exception:
                        pass

            external_script_domains = set()
            for script in page.query_selector_all("script"):
                src = script.get_attribute("src")
                if src:
                    try:
                        script_domain = urlparse(urljoin(url, src)).netloc.lower().split(":")[0]
                        if script_domain:
                            external_script_domains.add(script_domain)
                    except Exception:
                        pass
                    continue
                # Inline script - check its text content for fetch/XHR targets
                content = script.inner_text() or ""
                for match in _FETCH_XHR_PATTERN.finditer(content):
                    try:
                        target_domain = urlparse(match.group(1)).netloc.lower().split(":")[0]
                        if target_domain:
                            external_script_domains.add(target_domain)
                    except Exception:
                        pass

            page.close()
            browser.close()

        return hidden_iframe_domains, external_script_domains
    except Exception:
        return None


def check_page_source(url: str, domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    result = _inspect_page(url)
    if result is None:
        return []

    hidden_iframe_domains, external_script_domains = result
    out = []
    own_registered = domain.split(":")[0]

    def _is_external(other_domain: str) -> bool:
        return other_domain != own_registered and not other_domain.endswith("." + own_registered)

    external_hidden_iframes = {d for d in hidden_iframe_domains if _is_external(d)}
    if external_hidden_iframes:
        out.append((
            f"Page contains hidden iframe(s) loading external content: {', '.join(sorted(external_hidden_iframes))}",
            20
        ))

    external_scripts = {d for d in external_script_domains if _is_external(d)}
    if external_scripts:
        pts = min(15, len(external_scripts) * 8)
        out.append((
            f"Page loads or sends data to external script endpoint(s): {', '.join(sorted(external_scripts))}",
            pts
        ))

    return out
