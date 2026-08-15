content = open("detectors/message_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.email_auth import check_email_auth"
new_import = old_import + "\nfrom detectors.header_consistency import check_header_consistency"
assert old_import in content, "email_auth import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_sig = "def analyze_message(text, sender_domain=None):"
new_sig = "def analyze_message(text, sender_domain=None, eml_filepath=None):"
assert old_sig in content, "signature not found — aborting"
content = content.replace(old_sig, new_sig, 1)

old_block = """    email_auth_result = None
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
                verdict = "Suspicious\""""

new_block = old_block + """

    if eml_filepath:
        for hc_message, hc_points in check_header_consistency(eml_filepath):
            flags.append((hc_message, hc_points))
            final_score = min(final_score + hc_points, 100)
            if final_score >= 61:
                verdict = "Dangerous"
            elif final_score >= 31:
                verdict = "Suspicious\""""

assert old_block in content, "email_auth block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/message_analyzer.py", "w", encoding="utf-8").write(content)
print("message_analyzer.py patched — header consistency wired in")
