content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.dns_analyzer import check_dns"
new_import = old_import + "\nfrom detectors.asn_analyzer import check_asn"
assert old_import in content, "dns_analyzer import not found — aborting"
content = content.replace(old_import, new_import, 1)

old_block = """    if not is_ip_address:
        # MX/NS/TXT are conventionally apex-zone records; checking them
        # against a subdomain (e.g. www.example.com) produces false
        # positives since subdomains routinely have none of their own.
        dns_domain = registered_domain if registered_domain else domain.split(":")[0]
        for dns_message, dns_points in check_dns(dns_domain):
            flags.append((dns_message, dns_points))
            score += dns_points"""

new_block = """    if not is_ip_address:
        # MX/NS/TXT are conventionally apex-zone records; checking them
        # against a subdomain (e.g. www.example.com) produces false
        # positives since subdomains routinely have none of their own.
        dns_domain = registered_domain if registered_domain else domain.split(":")[0]
        for dns_message, dns_points in check_dns(dns_domain):
            flags.append((dns_message, dns_points))
            score += dns_points

        # ASN/hosting is a property of the actual serving host, not
        # necessarily the apex — check against the literal requested domain.
        host_domain = domain.split(":")[0]
        for asn_message, asn_points in check_asn(host_domain):
            flags.append((asn_message, asn_points))
            score += asn_points"""

assert old_block in content, "Step 3 DNS block not found — aborting"
content = content.replace(old_block, new_block, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — ASN check wired in")
