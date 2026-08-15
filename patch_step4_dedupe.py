content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import_dup = "from detectors.asn_analyzer import check_asn\nfrom detectors.asn_analyzer import check_asn"
new_import = "from detectors.asn_analyzer import check_asn"
assert old_import_dup in content, "duplicate import pattern not found — aborting"
content = content.replace(old_import_dup, new_import, 1)

old_dup_block = """

        # ASN/hosting is a property of the actual serving host, not
        # necessarily the apex — check against the literal requested domain.
        for asn_message, asn_points in check_asn(dns_domain if False else domain.split(":")[0]):
            flags.append((asn_message, asn_points))
            score += asn_points"""

assert old_dup_block in content, "duplicate ASN block not found — aborting"
content = content.replace(old_dup_block, "", 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py cleaned — duplicate import and ASN block removed")
