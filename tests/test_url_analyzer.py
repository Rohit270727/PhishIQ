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
