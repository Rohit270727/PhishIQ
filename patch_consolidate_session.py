content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.redirect_chain_analyzer import check_redirect_chain"
new_import = old_import + "\nfrom detectors.page_session import open_scan_session, close_scan_session"
assert old_import in content, "redirect_chain_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        for fv_message, fv_points in check_favicon(url, host_domain):
            flags.append((fv_message, fv_points))
            score += fv_points

        for cf_message, cf_points in check_credential_forms(url, host_domain):
            flags.append((cf_message, cf_points))
            score += cf_points

        for ps_message, ps_points in check_page_source(url, host_domain):
            flags.append((ps_message, ps_points))
            score += ps_points

        for fc_message, fc_points in check_fake_captcha(url, host_domain):
            flags.append((fc_message, fc_points))
            score += fc_points"""

new_block = """        _pw, _browser, _page = open_scan_session(url)
        try:
            for fv_message, fv_points in check_favicon(_page, url, host_domain):
                flags.append((fv_message, fv_points))
                score += fv_points

            for cf_message, cf_points in check_credential_forms(_page, url, host_domain):
                flags.append((cf_message, cf_points))
                score += cf_points

            for ps_message, ps_points in check_page_source(_page, url, host_domain):
                flags.append((ps_message, ps_points))
                score += ps_points

            for fc_message, fc_points in check_fake_captcha(_page, url, host_domain):
                flags.append((fc_message, fc_points))
                score += fc_points
        finally:
            close_scan_session(_pw, _browser)"""

assert old_block in content, "four-check block not found — aborting (whitespace/formatting may not match exactly)"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — consolidated to single shared Playwright session")
