"""
Threat-intelligence checks: VirusTotal, Google Safe Browsing, PhishTank.

Each service is optional and independently gated on an API key being
present in the environment (via config.Config). If a key is missing,
that service is skipped silently - no flag, no score impact, no error -
so this module is safe to import and call even with zero keys configured.

Network calls are wrapped individually: a timeout, connection error, or
malformed response from one service never blocks the other two, and
never blocks the rest of analyze_url()'s scoring pipeline.
"""

import base64
import requests

from config import Config

REQUEST_TIMEOUT = 6


def _vt_url_id(url):
    """VirusTotal v3 identifies URLs by unpadded URL-safe base64 of the URL string."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_virustotal(url):
    """
    Look up an existing VirusTotal report for this URL.

    Uses the lookup-only GET endpoint (no submission) to stay well within
    the free tier's 4 req/min limit. If VirusTotal has never seen this URL
    before, returns None rather than submitting a fresh scan, since scan
    results aren't available synchronously.
    """
    api_key = getattr(Config, "VIRUSTOTAL_API_KEY", None)
    if not api_key:
        return None

    try:
        url_id = _vt_url_id(url)
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        flagged = malicious + suspicious

        if flagged == 0:
            return None

        if flagged >= 5:
            points = 40
        elif flagged >= 2:
            points = 30
        else:
            points = 18

        return (
            f"Flagged by {flagged} security vendor(s) on VirusTotal "
            f"({malicious} malicious, {suspicious} suspicious)",
            points,
        )
    except (requests.RequestException, KeyError, ValueError):
        return None


def check_safe_browsing(url):
    """Check the URL against Google Safe Browsing's threat lists."""
    api_key = getattr(Config, "SAFE_BROWSING_API_KEY", None)
    if not api_key:
        return None

    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "phishiq", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None

        matches = resp.json().get("matches")
        if not matches:
            return None

        threat_types = sorted({m["threatType"] for m in matches})
        return (
            f"Listed on Google Safe Browsing ({', '.join(threat_types)})",
            45,
        )
    except (requests.RequestException, KeyError, ValueError):
        return None


def check_phishtank(url):
    """Check the URL against the PhishTank community-verified phish database."""
    api_key = getattr(Config, "PHISHTANK_API_KEY", None)
    if not api_key:
        return None

    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": api_key},
            headers={"User-Agent": "phishtank/phishiq"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None

        results = resp.json().get("results", {})
        if not results.get("in_database"):
            return None

        if results.get("verified"):
            return ("Verified phishing site listed on PhishTank", 40)
        return ("Reported as suspected phishing on PhishTank (unverified)", 20)
    except (requests.RequestException, KeyError, ValueError):
        return None


def check_threat_intel(url):
    """
    Run all configured threat-intel services and collect their (message, points)
    results. Mirrors check_homograph()'s return shape so it plugs into
    url_analyzer.py's flags/score accumulation the same way.
    """
    results = []
    for check in (check_virustotal, check_safe_browsing, check_phishtank):
        hit = check(url)
        if hit:
            results.append(hit)
    return results
