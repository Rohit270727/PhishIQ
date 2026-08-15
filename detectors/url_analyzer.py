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
from detectors.query_param_analyzer import analyze_query_params
from detectors.favicon_analyzer import check_favicon
from detectors.credential_form_analyzer import check_credential_forms

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

    for ti_message, ti_points in check_threat_intel(url_original):
        flags.append((ti_message, ti_points))
        score += ti_points

    if not is_ip_address:
        # MX/NS/TXT are conventionally apex-zone records; checking them
        # against a subdomain (e.g. www.example.com) produces false
        # positives since subdomains routinely have none of their own.
        dns_domain = registered_domain if registered_domain else domain.split(":")[0]
        for dns_message, dns_points in check_dns(dns_domain):
            flags.append((dns_message, dns_points))
            score += dns_points

        # ASN/hosting is a property of the actual serving host, not
        # necessarily the apex — check against the literal requested domain.
        host_domain = domain.split(":")[0]
        for asn_message, asn_points in check_asn(host_domain):
            flags.append((asn_message, asn_points))
            score += asn_points

        for qp_message, qp_points in analyze_query_params(url_original, host_domain):
            flags.append((qp_message, qp_points))
            score += qp_points

        for fv_message, fv_points in check_favicon(url, host_domain):
            flags.append((fv_message, fv_points))
            score += fv_points

        for cf_message, cf_points in check_credential_forms(url, host_domain):
            flags.append((cf_message, cf_points))
            score += cf_points

    domain_age = get_domain_age_days(domain)
    if domain_age is not None:
        if domain_age < 30:
            flags.append((f"Domain registered very recently ({domain_age} days ago)", 20))
            score += 20
        elif domain_age < 180:
            flags.append((f"Domain registered recently ({domain_age} days ago)", 10))
            score += 10

    if parsed.scheme == "https":
        cert_info = inspect_certificate(domain)
        if cert_info["valid"] and cert_info["is_free_ca"] and cert_info["cert_age_days"] is not None and cert_info["cert_age_days"] < 14:
            flags.append((f"Uses a freshly issued free SSL certificate ({cert_info['issuer']}, {cert_info['cert_age_days']} days old)", 12))
            score += 12

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


