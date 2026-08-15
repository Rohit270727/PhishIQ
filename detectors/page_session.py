"""
detectors/page_session.py
Shared Playwright page-loading helper. Launches one browser, opens one
page, navigates once, and returns the loaded page for multiple
detectors to inspect - avoiding the cost of each detector launching
its own browser independently.
"""
from playwright.sync_api import sync_playwright

_PAGE_LOAD_TIMEOUT_MS = 8000


def open_scan_session(url: str):
    """Returns (playwright_context, browser, page) on success, or
    (None, None, None) if the page failed to load. Caller MUST call
    close_scan_session() when done, even on the success path.
    Uses wait_until='domcontentloaded' rather than the 'load' default -
    we only need DOM structure (forms, scripts, iframes), not every
    image/font/analytics subresource to finish."""
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.goto(url, timeout=_PAGE_LOAD_TIMEOUT_MS, wait_until="domcontentloaded")
        return pw, browser, page
    except Exception:
        return None, None, None


def close_scan_session(pw, browser):
    try:
        if browser:
            browser.close()
    except Exception:
        pass
    try:
        if pw:
            pw.stop()
    except Exception:
        pass
