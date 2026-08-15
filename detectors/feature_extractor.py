import re
import math
from urllib.parse import urlparse

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link", "club", "loan", "win", "download"]
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm", "signin", "banking", "password", "billing", "suspend"]


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_url_features(raw_url):
    try:
        url = str(raw_url).strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()

        try:
            port = parsed.port
        except ValueError:
            port = None

        letters = sum(c.isalpha() for c in domain)
        digits = sum(c.isdigit() for c in domain)
        digit_letter_ratio = digits / (letters + 1)

        domain_core = domain.split(":")[0]

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            "num_dots": domain.count("."),
            "num_hyphens": domain.count("-"),
            "num_digits": digits,
            "num_at": url.count("@"),
            "num_subdomains": max(domain.count(".") - 1, 0),
            "has_ip": 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain_core) else 0,
            "has_https": 1 if parsed.scheme == "https" else 0,
            "has_port": 1 if port and port not in (80, 443) else 0,
            "suspicious_tld": 1 if domain.split(".")[-1].split(":")[0] in SUSPICIOUS_TLDS else 0,
            # NOTE: keyword_count and double_slash_in_path are computed on raw
            # (non-decoded) strings, matching how url_model.pkl was trained.
            # This means percent-encoded or HTML-entity-encoded obfuscation
            # (e.g. "%6c%6f%67%69%6e" for "login") will NOT increment
            # keyword_count or set double_slash_in_path here, even though
            # url_analyzer.py's rule-based checks (_normalize_for_analysis)
            # now catch this pattern independently. Do not "fix" this by
            # decoding here without retraining/re-evaluating url_model.pkl -
            # doing so would silently change feature semantics the model
            # was calibrated against. See patch discussion 2026-08-14.
            "keyword_count": sum(1 for k in SUSPICIOUS_KEYWORDS if k in full),
            "double_slash_in_path": 1 if "//" in path else 0,
            "digit_letter_ratio": round(digit_letter_ratio, 4),
            "domain_entropy": round(shannon_entropy(domain_core), 4),
            "https_literal_in_path": 1 if ("https" in path or "https" in query or "http" in path or "http" in query) else 0,
            "percent_encoded_count": full.count("%"),
            "num_query_params": query.count("=") if query else 0,
            "has_www": 1 if domain.startswith("www.") else 0,
            "num_special_chars": sum(1 for c in full if c in "!$&'()*+,;=~"),
        }
    except Exception:
        return {
            "url_length": len(str(raw_url)), "domain_length": 0, "path_length": 0,
            "num_dots": 0, "num_hyphens": 0, "num_digits": 0, "num_at": 0,
            "num_subdomains": 0, "has_ip": 0, "has_https": 0, "has_port": 0,
            "suspicious_tld": 0, "keyword_count": 0, "double_slash_in_path": 0,
            "digit_letter_ratio": 0, "domain_entropy": 0, "https_literal_in_path": 0,
            "percent_encoded_count": 0, "num_query_params": 0, "has_www": 0,
            "num_special_chars": 0,
        }


FEATURE_ORDER = [
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_digits", "num_at", "num_subdomains", "has_ip", "has_https",
    "has_port", "suspicious_tld", "keyword_count", "double_slash_in_path",
    "digit_letter_ratio", "domain_entropy", "https_literal_in_path",
    "percent_encoded_count", "num_query_params", "has_www", "num_special_chars"
]


def features_to_vector(features_dict):
    return [features_dict[k] for k in FEATURE_ORDER]
