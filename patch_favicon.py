content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.query_param_analyzer import analyze_query_params"
new_import = old_import + "\nfrom detectors.favicon_analyzer import check_favicon"
assert old_import in content, "query_param_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        for qp_message, qp_points in analyze_query_params(url_original, host_domain):
            flags.append((qp_message, qp_points))
            score += qp_points"""

new_block = old_block + """

        for fv_message, fv_points in check_favicon(url, host_domain):
            flags.append((fv_message, fv_points))
            score += fv_points"""

assert old_block in content, "query-param block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — favicon fingerprinting wired in")
