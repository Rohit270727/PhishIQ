content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old_import = "from detectors.threat_intel import check_threat_intel"
new_import = old_import + "\nfrom detectors.dns_analyzer import check_dns"
assert old_import in content, "import line not found — aborting"
content = content.replace(old_import, new_import, 1)

old_ip_check = """    if re.match(r"^(\\d{1,3}\\.){3}\\d{1,3}$", domain.split(":")[0]):
        flags.append(("Uses a raw IP address instead of a domain name", 25))
        score += 25"""

new_ip_check = """    is_ip_address = bool(re.match(r"^(\\d{1,3}\\.){3}\\d{1,3}$", domain.split(":")[0]))
    if is_ip_address:
        flags.append(("Uses a raw IP address instead of a domain name", 25))
        score += 25"""

assert old_ip_check in content, "IP-check block not found — aborting"
content = content.replace(old_ip_check, new_ip_check, 1)

old_ti_loop = """    for ti_message, ti_points in check_threat_intel(url_original):
        flags.append((ti_message, ti_points))
        score += ti_points"""

new_ti_loop = old_ti_loop + """

    if not is_ip_address:
        dns_domain = domain.split(":")[0]
        for dns_message, dns_points in check_dns(dns_domain):
            flags.append((dns_message, dns_points))
            score += dns_points"""

assert old_ti_loop in content, "threat_intel loop not found — aborting"
content = content.replace(old_ti_loop, new_ti_loop, 1)

open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched successfully")
