content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.asn_analyzer import check_asn"
new_import = old_import + "\nfrom detectors.query_param_analyzer import analyze_query_params"
assert old_import in content, "asn_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """        # ASN/hosting is a property of the actual serving host, not
        # necessarily the apex — check against the literal requested domain.
        host_domain = domain.split(":")[0]
        for asn_message, asn_points in check_asn(host_domain):
            flags.append((asn_message, asn_points))
            score += asn_points"""

new_block = old_block + """

        for qp_message, qp_points in analyze_query_params(url_original, host_domain):
            flags.append((qp_message, qp_points))
            score += qp_points"""

assert old_block in content, "ASN block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — query-parameter analysis wired in")
