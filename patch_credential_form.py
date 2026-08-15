content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.favicon_analyzer import check_favicon"
new_import = old_import + "\nfrom detectors.credential_form_analyzer import check_credential_forms"
assert old_import in content, "favicon_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        for fv_message, fv_points in check_favicon(url, host_domain):
            flags.append((fv_message, fv_points))
            score += fv_points"""

new_block = old_block + """

        for cf_message, cf_points in check_credential_forms(url, host_domain):
            flags.append((cf_message, cf_points))
            score += cf_points"""

assert old_block in content, "favicon block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — credential-form detection wired in")
