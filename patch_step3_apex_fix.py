content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old = """    if not is_ip_address:
        dns_domain = domain.split(":")[0]
        for dns_message, dns_points in check_dns(dns_domain):
            flags.append((dns_message, dns_points))
            score += dns_points"""

new = """    if not is_ip_address:
        # MX/NS/TXT are conventionally apex-zone records; checking them
        # against a subdomain (e.g. www.example.com) produces false
        # positives since subdomains routinely have none of their own.
        dns_domain = registered_domain if registered_domain else domain.split(":")[0]
        for dns_message, dns_points in check_dns(dns_domain):
            flags.append((dns_message, dns_points))
            score += dns_points"""

assert old in content, "Step 3 DNS block not found — aborting"
content = content.replace(old, new, 1)
open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — DNS check now uses apex domain")
