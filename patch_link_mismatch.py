content = open("detectors/message_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.header_consistency import check_header_consistency"
new_import = old_import + "\nfrom detectors.file_extractor import extract_html_body\nfrom detectors.link_mismatch_detector import check_link_text_mismatch"
assert old_import in content, "header_consistency import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """    if eml_filepath:
        for hc_message, hc_points in check_header_consistency(eml_filepath):
            flags.append((hc_message, hc_points))
            final_score = min(final_score + hc_points, 100)
            if final_score >= 61:
                verdict = "Dangerous"
            elif final_score >= 31:
                verdict = "Suspicious\""""

new_block = old_block + """

        html_body = extract_html_body(eml_filepath, "eml")
        for lm_message, lm_points in check_link_text_mismatch(html_body):
            flags.append((lm_message, lm_points))
            final_score = min(final_score + lm_points, 100)
            if final_score >= 61:
                verdict = "Dangerous"
            elif final_score >= 31:
                verdict = "Suspicious\""""

assert old_block in content, "header_consistency block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/message_analyzer.py", "w", encoding="utf-8").write(content)
print("message_analyzer.py patched — link-text mismatch wired in")
