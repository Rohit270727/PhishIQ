import re
import os
import tldextract
from urllib.parse import urlparse
from detectors.ml_predictor import ml_url_probability, ml_url_ngram_probability
from detectors.typosquat_detector import check_typosquatting
from detectors.homograph_detector import check_homograph, decode_domain_for_ml
from detectors.whois_utils import get_domain_age_days
from detectors.ssl_utils import inspect_certificate
from detectors.feedback_adjuster import get_domain_tally, get_adjustment_for_domain
from detectors.threat_intel import check_threat_intel
from detectors.dns_analyzer import check_dns
from detectors.asn_analyzer import check_asn
from detectors.dangling_dns_analyzer import check_dangling_dns
from detectors.historical_dns_tracker import check_historical_dns
from detectors.ioc_correlation import check_ioc_correlation
from detectors.query_param_analyzer import analyze_query_params
from detectors.favicon_analyzer import check_favicon
from detectors.credential_form_analyzer import check_credential_forms
from detectors.page_source_analyzer import check_page_source
from detectors.fake_captcha_analyzer import check_fake_captcha
from detectors.redirect_chain_analyzer import check_redirect_chain
from detectors.page_session import open_scan_session, close_scan_session
from concurrent.futures import ThreadPoolExecutor
from flask import current_app

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link", "club", "loan", "win", "download"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"]
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm", "signin", "banking", "password", "billing", "suspend"]
BRAND_NAMES = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram", "netflix",
               "bankofamerica", "chase", "wellsfargo", "flipkart", "sbi", "hdfc", "icici", "whatsapp"]

TRUSTED_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "trusted_domains.txt")

def _load_trusted_domains():
    domains = set()
    try:
        with open(TRUSTED_DOMAINS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
    except FileNotFoundError:
        pass
    return domains

TRUSTED_DOMAINS = _load_trusted_domains()

import html
from urllib.parse import unquote

def _normalize_for_analysis(text, max_iterations=3):
    """Repeatedly percent-decode and HTML-entity-decode a string for
    content inspection (keyword/redirect checks), capped to avoid
    infinite loops on malformed input. Does not touch URL parsing â€”
    call only on already-parsed path/full strings, never on the raw
    URL before urlparse()."""
    prev = text
    for _ in range(max_iterations):
        decoded = html.unescape(unquote(prev))
        if decoded == prev:
            break
        prev = decoded
    return prev


def _run_playwright_checks(url, host_domain):
    """Runs the favicon / credential-form / page-source / fake-captcha
    checks, which share one Playwright page and must stay sequential
    relative to each other. Returns combined (message, points) tuples
    in order. Safe to run in a background thread alongside the other
    independent network checks in analyze_url().
    """
    results = []
    _pw, _browser, _page = open_scan_session(url)
    try:
        results.extend(check_favicon(_page, url, host_domain))
        results.extend(check_credential_forms(_page, url, host_domain))
        results.extend(check_page_source(_page, url, host_domain))
        results.extend(check_fake_captcha(_page, url, host_domain))
    finally:
        close_scan_session(_pw, _browser)
    return results


def _run_in_context(app, fn, *args, **kwargs):
    """Runs fn(*args, **kwargs) inside its own Flask app context.
    Needed because ThreadPoolExecutor worker threads don't inherit
    the app context that _run_async_scan() pushed in its own thread
    (app context is thread-local, not shared across threads).
    """
    with app.app_context():
        return fn(*args, **kwargs)


def analyze_url(raw_url):
    flags = []
    score = 0
    url_original = raw_url.strip()

    if not re.match(r"^https?://", url_original, re.IGNORECASE):
        url = "http://" + url_original
    else:
        url = url_original

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()
    full_decoded = _normalize_for_analysis(full)
    path_decoded = _normalize_for_analysis(path)
    if full_decoded != full:
        flags.append(("URL contains encoded characters (percent-encoding or HTML entities) that decode to different content", 8))
        score += 8

    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    is_trusted = registered_domain in TRUSTED_DOMAINS

    is_ip_address = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain.split(":")[0]))
    if is_ip_address:
        flags.append(("Uses a raw IP address instead of a domain name", 25))
        score += 25

    if parsed.scheme != "https":
        flags.append(("Connection is not secured with HTTPS", 15))
        score += 15

    if len(url_original) > 75:
        flags.append(("Unusually long URL (common obfuscation tactic)", 10))
        score += 10

    if "@" in url_original:
        flags.append(("Contains \"@\" symbol which can hide the real destination", 15))
        score += 15

    if domain.count(".") >= 3:
        flags.append(("Excessive number of subdomains", 10))
        score += 10

    if domain.count("-") >= 2 and not any(label.startswith("xn--") for label in domain.split(".")):
        flags.append(("Multiple hyphens in domain name", 8))
        score += 8

    for s in SHORTENERS:
        # Match the shortener as the actual registered domain, not as a
        # substring anywhere in the host (e.g. "t.co" inside "microsoft.com").
        if domain == s or domain.endswith("." + s):
            flags.append((f"Uses a URL shortening service ({s})", 15))
            score += 15
            break

    tld = domain.split(".")[-1].split(":")[0] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append((f"Domain uses a high-risk TLD (.{tld})", 15))
        score += 15

    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in full_decoded]
    if kw_hits:
        pts = min(20, len(kw_hits) * 7)
        flags.append((f"Contains suspicious keyword(s): {', '.join(kw_hits[:3])}", pts))
        score += pts

    if not is_trusted:
        for brand in BRAND_NAMES:
            if brand in domain and domain != brand + ".com" and not domain.endswith("." + brand + ".com"):
                flags.append((f"Possible brand impersonation of '{brand}' in domain", 20))
                score += 20
                break

    if "//" in path_decoded:
        flags.append(("Suspicious redirect pattern in URL path", 10))
        score += 10

    if parsed.port and parsed.port not in (80, 443):
        flags.append((f"Uses non-standard port ({parsed.port})", 10))
        score += 10

    typo_hit = check_typosquatting(domain)
    if typo_hit:
        flags.append((typo_hit["message"], 25))
        score += 25

    for hg_message, hg_points in check_homograph(domain):
        flags.append((hg_message, hg_points))
        score += hg_points

    executor = ThreadPoolExecutor(max_workers=10)
    _app = current_app._get_current_object()
    futures = {}
    futures["threat_intel"] = executor.submit(_run_in_context, _app, check_threat_intel, url_original)
    futures["domain_age"] = executor.submit(_run_in_context, _app, get_domain_age_days, domain)
    if parsed.scheme == "https":
        futures["cert"] = executor.submit(_run_in_context, _app, inspect_certificate, domain)

    if not is_ip_address:
        # MX/NS/TXT are conventionally apex-zone records; checking them
        # against a subdomain (e.g. www.example.com) produces false
        # positives since subdomains routinely have none of their own.
        dns_domain = registered_domain if registered_domain else domain.split(":")[0]
        # ASN/hosting is a property of the actual serving host, not
        # necessarily the apex - check against the literal requested domain.
        host_domain = domain.split(":")[0]

        futures["dns"] = executor.submit(_run_in_context, _app, check_dns, dns_domain)
        futures["asn"] = executor.submit(_run_in_context, _app, check_asn, host_domain)
        futures["dangling_dns"] = executor.submit(_run_in_context, _app, check_dangling_dns, host_domain)
        futures["historical_dns"] = executor.submit(_run_in_context, _app, check_historical_dns, host_domain)
        futures["ioc"] = executor.submit(_run_in_context, _app, check_ioc_correlation, host_domain)
        futures["query_params"] = executor.submit(_run_in_context, _app, analyze_query_params, url_original, host_domain)
        futures["redirect_chain"] = executor.submit(_run_in_context, _app, check_redirect_chain, url, host_domain)
        futures["playwright"] = executor.submit(_run_in_context, _app, _run_playwright_checks, url, host_domain)

    # Collect results in the same order they used to run sequentially, so
    # flag ordering in the output stays stable. Each .result() call just
    # waits on a future that likely already finished, since everything
    # above started running concurrently.
    for ti_message, ti_points in futures["threat_intel"].result():
        flags.append((ti_message, ti_points))
        score += ti_points

    if not is_ip_address:
        for dns_message, dns_points in futures["dns"].result():
            flags.append((dns_message, dns_points))
            score += dns_points

        for asn_message, asn_points in futures["asn"].result():
            flags.append((asn_message, asn_points))
            score += asn_points
        for dd_message, dd_points in futures["dangling_dns"].result():
            flags.append((dd_message, dd_points))
            score += dd_points
        for hd_message, hd_points in futures["historical_dns"].result():
            flags.append((hd_message, hd_points))
            score += hd_points
        for ioc_message, ioc_points in futures["ioc"].result():
            flags.append((ioc_message, ioc_points))
            score += ioc_points

        for qp_message, qp_points in futures["query_params"].result():
            flags.append((qp_message, qp_points))
            score += qp_points

        for fv_message, fv_points in futures["playwright"].result():
            flags.append((fv_message, fv_points))
            score += fv_points

        for rc_message, rc_points in futures["redirect_chain"].result():
            flags.append((rc_message, rc_points))
            score += rc_points

    domain_age = futures["domain_age"].result()
    if domain_age is not None:
        if domain_age < 30:
            flags.append((f"Domain registered very recently ({domain_age} days ago)", 20))
            score += 20
        elif domain_age < 180:
            flags.append((f"Domain registered recently ({domain_age} days ago)", 10))
            score += 10

    if parsed.scheme == "https":
        cert_info = futures["cert"].result()
        if cert_info["valid"] and cert_info["is_free_ca"] and cert_info["cert_age_days"] is not None and cert_info["cert_age_days"] < 14:
            flags.append((f"Uses a freshly issued free SSL certificate ({cert_info['issuer']}, {cert_info['cert_age_days']} days old)", 12))
            score += 12

    executor.shutdown(wait=False)

    heuristic_score = min(score, 100)

    ml_prob = ml_url_probability(url_original)
    ngram_prob = ml_url_ngram_probability(url_original)

    ml_scores = []
    if ml_prob is not None:
        ml_scores.append(round(ml_prob * 100))
    if ngram_prob is not None:
        ngram_score = round(ngram_prob * 100)
        ml_scores.append(ngram_score)
        flags.append((f"Character-pattern model confidence: {ngram_score}% phishing probability", 0))

    has_punycode_flag = any("punycode-encoded" in msg for msg, _ in flags)

    if ml_scores:
        avg_ml_score = sum(ml_scores) / len(ml_scores)
        if is_trusted:
            final_score = round(0.85 * heuristic_score + 0.15 * avg_ml_score)
            flags.append((f"Registered domain '{registered_domain}' matched trusted allowlist â€” ML score dampened", 0))
        elif has_punycode_flag:
            final_score = round(0.75 * heuristic_score + 0.25 * avg_ml_score)
            flags.append(("Internationalized domain - character-pattern model dampened (not trained on IDN domains)", 0))
        else:
            final_score = round(0.4 * heuristic_score + 0.6 * avg_ml_score)
    else:
        final_score = heuristic_score

    domain_tally = get_domain_tally(registered_domain)
    adj_points, adj_reason = get_adjustment_for_domain(domain_tally)
    if adj_reason:
        flags.append((adj_reason, adj_points))
        final_score = max(0, min(100, final_score + adj_points))

    verdict = "Safe"
    if final_score >= 61:
        verdict = "Dangerous"
    elif final_score >= 31:
        verdict = "Suspicious"

    if not flags:
        flags.append(("No known phishing indicators detected", 0))

    return {"score": final_score, "verdict": verdict, "flags": flags}


