content = open("detectors/message_analyzer.py", encoding="utf-8").read()

old_sig = "def analyze_message(text):"
new_sig = "def analyze_message(text, sender_domain=None):"
assert old_sig in content, "signature not found — aborting"
content = content.replace(old_sig, new_sig, 1)

old_import = "from detectors.ml_predictor import ml_message_probability"
new_import = old_import + "\nfrom detectors.email_auth import check_email_auth"
assert old_import in content, "import line not found — aborting"
content = content.replace(old_import, new_import, 1)

old_return = "if not flags:\n        flags.append((\"No known phishing/scam indicators detected\", 0))\n\n    return {\"score\": final_score, \"verdict\": verdict, \"flags\": flags}"

new_return = """email_auth_result = None
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

    if not flags:
        flags.append(("No known phishing/scam indicators detected", 0))

    return {"score": final_score, "verdict": verdict, "flags": flags, "email_auth": email_auth_result}"""

assert old_return in content, "return block not found — aborting"
content = content.replace(old_return, new_return, 1)

open("detectors/message_analyzer.py", "w", encoding="utf-8").write(content)
print("message_analyzer.py patched successfully")
