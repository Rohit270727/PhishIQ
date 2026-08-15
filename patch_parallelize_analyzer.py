"""
Patches detectors/url_analyzer.py to run the independent network-bound
checks (threat intel, DNS, ASN, dangling DNS, historical DNS, IOC
correlation, query params, redirect chain, WHOIS domain age, SSL cert,
and the Playwright favicon/credential-form/page-source/fake-captcha
group) concurrently instead of sequentially.

Worst case goes from ~sum-of-all-timeouts (~38s) down to roughly the
slowest single check (~8s for the Playwright page load), since they
all start at once.

Flag/score output is unchanged - only collection order matters, and
results are applied back in the exact same order they used to run in,
so behavior and output are identical, just faster.

Run this from the PhishIQ project root:
    python patch_parallelize_analyzer.py
"""

import re

PATH = "detectors/url_analyzer.py"

with open(PATH, "r", encoding="utf-8-sig") as f:
    lines = f.readlines()


def find_line(target, start=0):
    """Find the index of the first line whose stripped content exactly
    matches target, searching from index `start`."""
    for i in range(start, len(lines)):
        if lines[i].strip() == target:
            return i
    raise ValueError(f"Could not find anchor line: {target!r}")


# ---------------------------------------------------------------------
# 1. Add the ThreadPoolExecutor import, right after the page_session
#    import (last import line in the detector-import block).
# ---------------------------------------------------------------------
import_anchor = find_line(
    "from detectors.page_session import open_scan_session, close_scan_session"
)
lines.insert(import_anchor + 1, "from concurrent.futures import ThreadPoolExecutor\n")

# ---------------------------------------------------------------------
# 2. Insert the _run_playwright_checks() helper right before
#    "def analyze_url(raw_url):". Re-find the anchor since we just
#    shifted line numbers by inserting the import above.
# ---------------------------------------------------------------------
analyze_url_def = find_line("def analyze_url(raw_url):")

helper_lines = [
    "def _run_playwright_checks(url, host_domain):\n",
    '    """Runs the favicon / credential-form / page-source / fake-captcha\n',
    "    checks, which share one Playwright page and must stay sequential\n",
    "    relative to each other. Returns combined (message, points) tuples\n",
    "    in order. Safe to run in a background thread alongside the other\n",
    "    independent network checks in analyze_url().\n",
    '    """\n',
    "    results = []\n",
    "    _pw, _browser, _page = open_scan_session(url)\n",
    "    try:\n",
    "        results.extend(check_favicon(_page, url, host_domain))\n",
    "        results.extend(check_credential_forms(_page, url, host_domain))\n",
    "        results.extend(check_page_source(_page, url, host_domain))\n",
    "        results.extend(check_fake_captcha(_page, url, host_domain))\n",
    "    finally:\n",
    "        close_scan_session(_pw, _browser)\n",
    "    return results\n",
    "\n",
    "\n",
]

lines[analyze_url_def:analyze_url_def] = helper_lines

# ---------------------------------------------------------------------
# 3. Replace the sequential threat-intel / DNS / ASN / ... / redirect-
#    chain block with a parallel version using a ThreadPoolExecutor.
#    Anchors re-found again since indices shifted after step 2's insert.
# ---------------------------------------------------------------------
span_a_start = find_line("for ti_message, ti_points in check_threat_intel(url_original):")
span_a_end = find_line("score += rc_points", start=span_a_start)

span_a_new = """    executor = ThreadPoolExecutor(max_workers=10)
    futures = {}
    futures["threat_intel"] = executor.submit(check_threat_intel, url_original)
    futures["domain_age"] = executor.submit(get_domain_age_days, domain)
    if parsed.scheme == "https":
        futures["cert"] = executor.submit(inspect_certificate, domain)

    if not is_ip_address:
        # MX/NS/TXT are conventionally apex-zone records; checking them
        # against a subdomain (e.g. www.example.com) produces false
        # positives since subdomains routinely have none of their own.
        dns_domain = registered_domain if registered_domain else domain.split(":")[0]
        # ASN/hosting is a property of the actual serving host, not
        # necessarily the apex - check against the literal requested domain.
        host_domain = domain.split(":")[0]

        futures["dns"] = executor.submit(check_dns, dns_domain)
        futures["asn"] = executor.submit(check_asn, host_domain)
        futures["dangling_dns"] = executor.submit(check_dangling_dns, host_domain)
        futures["historical_dns"] = executor.submit(check_historical_dns, host_domain)
        futures["ioc"] = executor.submit(check_ioc_correlation, host_domain)
        futures["query_params"] = executor.submit(analyze_query_params, url_original, host_domain)
        futures["redirect_chain"] = executor.submit(check_redirect_chain, url, host_domain)
        futures["playwright"] = executor.submit(_run_playwright_checks, url, host_domain)

    # Collect results in the same order they used to run sequentially, so
    # flag ordering in the output stays stable. Each .result() call just
    # waits on a future that likely already finished, since everything
    # above started running concurrently.
    for ti_message, ti_points in futures["threat_intel"].result():
        flags.append((ti_message, ti_points))
        score += ti_points

    if not is_ip_address:
        for dns_message, dns_points in futures["dns"].result():
            flags.append((dns_message, dns_points))
            score += dns_points

        for asn_message, asn_points in futures["asn"].result():
            flags.append((asn_message, asn_points))
            score += asn_points
        for dd_message, dd_points in futures["dangling_dns"].result():
            flags.append((dd_message, dd_points))
            score += dd_points
        for hd_message, hd_points in futures["historical_dns"].result():
            flags.append((hd_message, hd_points))
            score += hd_points
        for ioc_message, ioc_points in futures["ioc"].result():
            flags.append((ioc_message, ioc_points))
            score += ioc_points

        for qp_message, qp_points in futures["query_params"].result():
            flags.append((qp_message, qp_points))
            score += qp_points

        for fv_message, fv_points in futures["playwright"].result():
            flags.append((fv_message, fv_points))
            score += fv_points

        for rc_message, rc_points in futures["redirect_chain"].result():
            flags.append((rc_message, rc_points))
            score += rc_points
"""

lines[span_a_start:span_a_end + 1] = [span_a_new]

# ---------------------------------------------------------------------
# 4. Replace the sequential WHOIS / SSL-cert block to consume the
#    futures created above instead of calling the functions directly,
#    and shut the executor down afterward.
# ---------------------------------------------------------------------
span_b_start = find_line("domain_age = get_domain_age_days(domain)")
span_b_end = find_line("score += 12", start=span_b_start)

span_b_new = """    domain_age = futures["domain_age"].result()
    if domain_age is not None:
        if domain_age < 30:
            flags.append((f"Domain registered very recently ({domain_age} days ago)", 20))
            score += 20
        elif domain_age < 180:
            flags.append((f"Domain registered recently ({domain_age} days ago)", 10))
            score += 10

    if parsed.scheme == "https":
        cert_info = futures["cert"].result()
        if cert_info["valid"] and cert_info["is_free_ca"] and cert_info["cert_age_days"] is not None and cert_info["cert_age_days"] < 14:
            flags.append((f"Uses a freshly issued free SSL certificate ({cert_info['issuer']}, {cert_info['cert_age_days']} days old)", 12))
            score += 12

    executor.shutdown(wait=False)
"""

lines[span_b_start:span_b_end + 1] = [span_b_new]

with open(PATH, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("url_analyzer.py parallelized successfully")
