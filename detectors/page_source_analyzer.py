"""
detectors/page_source_analyzer.py
Inspects an already-loaded page for hidden iframes and external
resource references. Takes a Playwright `page` object rather than
launching its own browser per call.
"""
import re
from urllib.parse import urljoin, urlparse

_FETCH_XHR_PATTERN = re.compile(
    r"""(?:fetch\s*\(\s*|\.open\s*\(\s*['"]\w+['"]\s*,\s*)['"](https?://[^'"]+)['"]""",
    re.IGNORECASE
)


def _is_hidden(el) -> bool:
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


def check_page_source(page, url: str, domain: str) -> list:
    """Returns (message, points) tuples. `page` must already be loaded
    by the caller (see page_session.py)."""
    if page is None:
        return []

    try:
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
            content = script.inner_text() or ""
            for match in _FETCH_XHR_PATTERN.finditer(content):
                try:
                    target_domain = urlparse(match.group(1)).netloc.lower().split(":")[0]
                    if target_domain:
                        external_script_domains.add(target_domain)
                except Exception:
                    pass
    except Exception:
        return []

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
