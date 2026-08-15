"""
detectors/redirect_chain_analyzer.py
Follows a URL's HTTP redirect chain manually (not via requests'
allow_redirects=True, which hides intermediate hops) and scores the
chain's shape: many hops, a suspicious-TLD/shortener domain appearing
mid-chain rather than as the visible entry point, an HTTPS-to-HTTP
downgrade, or a redirect loop are all evasion patterns phishing links
use specifically to defeat naive first-hop or final-hop-only analysis.
"""
import requests
from urllib.parse import urlparse

_MAX_HOPS = 10
_REQUEST_TIMEOUT = 6

_SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link", "club", "loan", "win", "download"]
_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"]


def _follow_chain(start_url: str):
    """Returns a list of (url, status_code, scheme) tuples representing
    each hop, in order, up to _MAX_HOPS. Stops early on a non-redirect
    status, a request failure, or a detected loop. Never raises —
    caller gets whatever chain was captured before any failure."""
    chain = []
    seen_urls = set()
    current_url = start_url

    for _ in range(_MAX_HOPS):
        if current_url in seen_urls:
            chain.append((current_url, "LOOP_DETECTED", urlparse(current_url).scheme))
            break
        seen_urls.add(current_url)

        try:
            resp = requests.get(current_url, timeout=_REQUEST_TIMEOUT, allow_redirects=False, stream=True)
        except requests.RequestException:
            break

        scheme = urlparse(current_url).scheme
        chain.append((current_url, resp.status_code, scheme))

        if resp.status_code in (301, 302, 303, 307, 308):
            next_url = resp.headers.get("Location")
            if not next_url:
                break
            if next_url.startswith("/"):
                parsed = urlparse(current_url)
                next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
            current_url = next_url
        else:
            break

    return chain


def check_redirect_chain(url: str, domain: str) -> list:
    """Returns (message, points) tuples for url_analyzer's scoring loop."""
    chain = _follow_chain(url)
    if len(chain) <= 1:
        return []  # no redirect occurred, nothing to score

    out = []
    hop_count = len(chain)

    if hop_count >= 4:
        out.append((f"URL redirects through an unusually long chain ({hop_count} hops)", 15))
    elif hop_count >= 3:
        out.append((f"URL redirects through {hop_count} hops", 8))

    if chain[-1][1] == "LOOP_DETECTED":
        out.append(("URL redirect chain loops back on itself", 15))

    mid_chain_flagged = set()
    for hop_url, status, scheme in chain[1:]:  # skip the entry point itself
        hop_domain = urlparse(hop_url).netloc.lower().split(":")[0]
        if not hop_domain or hop_domain in mid_chain_flagged:
            continue
        tld = hop_domain.split(".")[-1] if "." in hop_domain else ""
        if tld in _SUSPICIOUS_TLDS:
            out.append((f"Redirect chain passes through a high-risk-TLD domain ({hop_domain})", 15))
            mid_chain_flagged.add(hop_domain)
        elif any(hop_domain == s or hop_domain.endswith("." + s) for s in _SHORTENERS):
            out.append((f"Redirect chain passes through a URL shortener mid-chain ({hop_domain})", 12))
            mid_chain_flagged.add(hop_domain)

    for i in range(len(chain) - 1):
        if chain[i][2] == "https" and chain[i + 1][2] == "http":
            out.append(("Redirect chain downgrades from HTTPS to HTTP", 18))
            break

    return out
