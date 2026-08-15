content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.credential_form_analyzer import check_credential_forms"
new_import = old_import + "\nfrom detectors.page_source_analyzer import check_page_source"
assert old_import in content, "credential_form_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        for cf_message, cf_points in check_credential_forms(url, host_domain):
            flags.append((cf_message, cf_points))
            score += cf_points"""

new_block = old_block + """

        for ps_message, ps_points in check_page_source(url, host_domain):
            flags.append((ps_message, ps_points))
            score += ps_points"""

assert old_block in content, "credential-form block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — page-source analysis wired in")
