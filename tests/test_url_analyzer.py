import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detectors.url_analyzer import analyze_url


def test_safe_url_has_low_score():
    result = analyze_url("https://github.com")
    assert result["verdict"] == "Safe"
    assert result["score"] < 31


def test_http_only_url_flagged():
    result = analyze_url("http://example.com")
    reasons = [f[0] for f in result["flags"]]
    assert any("HTTPS" in r for r in reasons)


def test_ip_based_url_flagged():
    result = analyze_url("http://192.168.1.1/login")
    reasons = [f[0] for f in result["flags"]]
    assert any("raw IP address" in r for r in reasons)


def test_url_shortener_flagged():
    result = analyze_url("http://bit.ly/abc123")
    reasons = [f[0] for f in result["flags"]]
    assert any("shortening service" in r for r in reasons)


def test_suspicious_tld_flagged():
    result = analyze_url("http://freegift.tk")
    reasons = [f[0] for f in result["flags"]]
    assert any("high-risk TLD" in r for r in reasons)


def test_typosquat_url_is_dangerous():
    result = analyze_url("http://paypa1-secure.tk/login")
    assert result["verdict"] == "Dangerous"
    reasons = [f[0] for f in result["flags"]]
    assert any("typosquatting" in r for r in reasons)


def test_at_symbol_flagged():
    result = analyze_url("http://example.com@evil.com")
    reasons = [f[0] for f in result["flags"]]
    assert any("@" in r for r in reasons)


def test_long_url_flagged():
    long_url = "http://example.com/" + "a" * 100
    result = analyze_url(long_url)
    reasons = [f[0] for f in result["flags"]]
    assert any("Unusually long" in r for r in reasons)


def test_score_never_exceeds_100():
    result = analyze_url("http://paypa1-verify-secure-login-account.tk/update@evil.com//redirect")
    assert result["score"] <= 100


def test_verdict_matches_score_thresholds():
    result = analyze_url("https://google.com")
    if result["score"] >= 61:
        assert result["verdict"] == "Dangerous"
    elif result["score"] >= 31:
        assert result["verdict"] == "Suspicious"
    else:
        assert result["verdict"] == "Safe"

def test_percent_encoded_keyword_flagged():
    result = analyze_url("http://example.com/%6c%6f%67%69%6e")
    reasons = [f[0] for f in result["flags"]]
    assert any("encoded characters" in r for r in reasons)
    assert any("keyword" in r.lower() or "suspicious" in r.lower() for r in reasons)

def test_html_entity_keyword_flagged():
    result = analyze_url("http://example.com/&#108;ogin")
    reasons = [f[0] for f in result["flags"]]
    assert any("encoded characters" in r for r in reasons)
    assert any("keyword" in r.lower() or "suspicious" in r.lower() for r in reasons)

def test_double_percent_encoded_keyword_flagged():
    result = analyze_url("http://example.com/%256c%256f%2567%2569%256e")
    reasons = [f[0] for f in result["flags"]]
    assert any("encoded characters" in r for r in reasons)
    assert any("keyword" in r.lower() or "suspicious" in r.lower() for r in reasons)

def test_benign_double_slash_in_query_still_flagged():
    result = analyze_url("http://example.com/search/foo//bar")
    reasons = [f[0] for f in result["flags"]]
    assert any("redirect" in r.lower() for r in reasons)

def test_malformed_percent_sequence_does_not_crash():
    result = analyze_url("http://example.com/foo%zzbar%")
    assert isinstance(result["score"], int)
    assert isinstance(result["flags"], list)

def test_clean_url_no_encoding_flags():
    result = analyze_url("https://github.com/anthropic/docs")
    reasons = [f[0] for f in result["flags"]]
    assert not any("encoded characters" in r for r in reasons)

def test_quadruple_encoded_input_terminates_cleanly():
    result = analyze_url("http://example.com/%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%33%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%37%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%39%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%35")
    assert isinstance(result["score"], int)
    assert isinstance(result["flags"], list)
    assert 0 <= result["score"] <= 100
