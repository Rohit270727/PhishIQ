content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.fake_captcha_analyzer import check_fake_captcha"
new_import = old_import + "\nfrom detectors.redirect_chain_analyzer import check_redirect_chain"
assert old_import in content, "fake_captcha_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        for fc_message, fc_points in check_fake_captcha(url, host_domain):
            flags.append((fc_message, fc_points))
            score += fc_points"""

new_block = old_block + """

        for rc_message, rc_points in check_redirect_chain(url, host_domain):
            flags.append((rc_message, rc_points))
            score += rc_points"""

assert old_block in content, "fake-captcha block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — redirect-chain analysis wired in")
