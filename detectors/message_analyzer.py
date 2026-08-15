import re
from detectors.ml_predictor import ml_message_probability
from detectors.email_auth import check_email_auth
from detectors.header_consistency import check_header_consistency
from detectors.file_extractor import extract_html_body
from detectors.link_mismatch_detector import check_link_text_mismatch

URGENCY_WORDS = ["urgent", "immediately", "act now", "expire", "expiring", "suspended",
                 "verify now", "limited time", "act fast", "last chance", "final notice"]
MONEY_WORDS = ["winner", "won", "prize", "free", "claim", "cash", "lottery", "gift card", "reward", "jackpot", "refund"]
SENSITIVE_REQUESTS = ["password", "otp", "pin", "card number", "cvv", "ssn", "aadhar", "bank account", "atm pin", "social security"]
THREAT_WORDS = ["suspended", "legal action", "penalty", "blocked", "terminated", "arrest", "fine", "account will be closed"]
GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear account holder"]

URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+)", re.IGNORECASE)

def analyze_message(text, sender_domain=None, eml_filepath=None):
    flags = []
    score = 0
    t = text.lower()

    urgency_hits = [w for w in URGENCY_WORDS if w in t]
    if urgency_hits:
        pts = min(20, len(urgency_hits) * 10)
        flags.append((f"Creates false urgency: '{urgency_hits[0]}'", pts))
        score += pts

    money_hits = [w for w in MONEY_WORDS if w in t]
    if money_hits:
        pts = min(20, len(money_hits) * 10)
        flags.append((f"Promises unexpected money/prize: '{money_hits[0]}'", pts))
        score += pts

    sensitive_hits = [w for w in SENSITIVE_REQUESTS if w in t]
    if sensitive_hits:
        flags.append((f"Requests sensitive information: '{sensitive_hits[0]}'", 25))
        score += 25

    threat_hits = [w for w in THREAT_WORDS if w in t]
    if threat_hits:
        flags.append((f"Uses threatening language: '{threat_hits[0]}'", 15))
        score += 15

    greeting_hits = [w for w in GENERIC_GREETINGS if w in t]
    if greeting_hits:
        flags.append(("Uses a generic, impersonal greeting", 8))
        score += 8

    urls_found = URL_PATTERN.findall(text)
    if urls_found:
        flags.append((f"Contains {len(urls_found)} embedded link(s)", 15))
        score += 15
        for u in urls_found:
            for s in ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "cutt.ly"]:
                if s in u.lower():
                    flags.append((f"Contains a shortened link ({s}) hiding the real destination", 10))
                    score += 10
                    break

    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.3 and len(text) > 15:
        flags.append(("Excessive use of capital letters", 8))
        score += 8

    if text.count("!") >= 3:
        flags.append(("Excessive use of exclamation marks", 5))
        score += 5

    heuristic_score = min(score, 100)

    ml_prob = ml_message_probability(text)
    if ml_prob is not None:
        ml_score = round(ml_prob * 100)
        final_score = round(0.5 * heuristic_score + 0.5 * ml_score)
        flags.append((f"ML model confidence: {ml_score}% scam probability", 0))
    else:
        final_score = heuristic_score

    verdict = "Safe"
    if final_score >= 61:
        verdict = "Dangerous"
    elif final_score >= 31:
        verdict = "Suspicious"

    email_auth_result = None
    if sender_domain:
        email_auth_result = check_email_auth(sender_domain)
        auth_pts = email_auth_result["email_auth_risk_score"]
        if auth_pts > 0:
            note = email_auth_result["all_notes"][0] if email_auth_result["all_notes"] else "Sender domain authentication issue"
            flags.append((f"Sender domain email authentication: {note}", auth_pts))
            final_score = min(final_score + auth_pts, 100)
            if final_score >= 61:
                verdict = "Dangerous"
            elif final_score >= 31:
                verdict = "Suspicious"

    if eml_filepath:
        for hc_message, hc_points in check_header_consistency(eml_filepath):
            flags.append((hc_message, hc_points))
            final_score = min(final_score + hc_points, 100)
            if final_score >= 61:
                verdict = "Dangerous"
            elif final_score >= 31:
                verdict = "Suspicious"

        html_body = extract_html_body(eml_filepath, "eml")
        for lm_message, lm_points in check_link_text_mismatch(html_body):
            flags.append((lm_message, lm_points))
            final_score = min(final_score + lm_points, 100)
            if final_score >= 61:
                verdict = "Dangerous"
            elif final_score >= 31:
                verdict = "Suspicious"

    if not flags:
        flags.append(("No known phishing/scam indicators detected", 0))

    return {"score": final_score, "verdict": verdict, "flags": flags, "email_auth": email_auth_result}