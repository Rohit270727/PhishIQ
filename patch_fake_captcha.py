content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.page_source_analyzer import check_page_source"
new_import = old_import + "\nfrom detectors.fake_captcha_analyzer import check_fake_captcha"
assert old_import in content, "page_source_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        for ps_message, ps_points in check_page_source(url, host_domain):
            flags.append((ps_message, ps_points))
            score += ps_points"""

new_block = old_block + """

        for fc_message, fc_points in check_fake_captcha(url, host_domain):
            flags.append((fc_message, fc_points))
            score += fc_points"""

assert old_block in content, "page-source block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — fake CAPTCHA detection wired in")
