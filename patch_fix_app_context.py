"""
Fixes "Working outside of application context" errors introduced by
patch_parallelize_analyzer.py.

ThreadPoolExecutor spawns its own worker threads, which do NOT inherit
the Flask app context that _run_async_scan() pushed in its own thread
(app context is thread-local). Any submitted check that touches the DB
or app.config (e.g. threat intel API keys, IOC correlation) fails on
those pool worker threads.

Fix: capture the real Flask app object once via current_app, and wrap
every executor.submit(...) call so each pooled task pushes its own
app.app_context() before running.

Run this from the PhishIQ project root, after patch_parallelize_analyzer.py:
    python patch_fix_app_context.py
"""

PATH = "detectors/url_analyzer.py"

with open(PATH, "r", encoding="utf-8-sig") as f:
    content = f.read()

original_content = content

# ---------------------------------------------------------------------
# 1. Add the current_app import alongside the ThreadPoolExecutor import.
# ---------------------------------------------------------------------
old = "from concurrent.futures import ThreadPoolExecutor\n"
new = "from concurrent.futures import ThreadPoolExecutor\nfrom flask import current_app\n"
if old not in content:
    raise SystemExit("Could not find ThreadPoolExecutor import - has the file changed?")
content = content.replace(old, new, 1)

# ---------------------------------------------------------------------
# 2. Add a _run_in_context helper right after _run_playwright_checks,
#    so every pooled task can push its own app context before running.
# ---------------------------------------------------------------------
old = "        close_scan_session(_pw, _browser)\n    return results\n\n\n"
new = (
    "        close_scan_session(_pw, _browser)\n"
    "    return results\n"
    "\n"
    "\n"
    "def _run_in_context(app, fn, *args, **kwargs):\n"
    '    """Runs fn(*args, **kwargs) inside its own Flask app context.\n'
    "    Needed because ThreadPoolExecutor worker threads don't inherit\n"
    "    the app context that _run_async_scan() pushed in its own thread\n"
    "    (app context is thread-local, not shared across threads).\n"
    '    """\n'
    "    with app.app_context():\n"
    "        return fn(*args, **kwargs)\n"
    "\n"
    "\n"
)
if old not in content:
    raise SystemExit("Could not find _run_playwright_checks end marker - has the file changed?")
content = content.replace(old, new, 1)

# ---------------------------------------------------------------------
# 3. Capture the real Flask app object once, right after the executor
#    is created.
# ---------------------------------------------------------------------
old = '    executor = ThreadPoolExecutor(max_workers=10)\n    futures = {}\n'
new = (
    '    executor = ThreadPoolExecutor(max_workers=10)\n'
    '    _app = current_app._get_current_object()\n'
    '    futures = {}\n'
)
if old not in content:
    raise SystemExit("Could not find executor creation line - has the file changed?")
content = content.replace(old, new, 1)

# ---------------------------------------------------------------------
# 4. Wrap every executor.submit(...) call so each task pushes its own
#    app context via _run_in_context before running the real function.
# ---------------------------------------------------------------------
submit_replacements = [
    (
        'futures["threat_intel"] = executor.submit(check_threat_intel, url_original)',
        'futures["threat_intel"] = executor.submit(_run_in_context, _app, check_threat_intel, url_original)',
    ),
    (
        'futures["domain_age"] = executor.submit(get_domain_age_days, domain)',
        'futures["domain_age"] = executor.submit(_run_in_context, _app, get_domain_age_days, domain)',
    ),
    (
        'futures["cert"] = executor.submit(inspect_certificate, domain)',
        'futures["cert"] = executor.submit(_run_in_context, _app, inspect_certificate, domain)',
    ),
    (
        'futures["dns"] = executor.submit(check_dns, dns_domain)',
        'futures["dns"] = executor.submit(_run_in_context, _app, check_dns, dns_domain)',
    ),
    (
        'futures["asn"] = executor.submit(check_asn, host_domain)',
        'futures["asn"] = executor.submit(_run_in_context, _app, check_asn, host_domain)',
    ),
    (
        'futures["dangling_dns"] = executor.submit(check_dangling_dns, host_domain)',
        'futures["dangling_dns"] = executor.submit(_run_in_context, _app, check_dangling_dns, host_domain)',
    ),
    (
        'futures["historical_dns"] = executor.submit(check_historical_dns, host_domain)',
        'futures["historical_dns"] = executor.submit(_run_in_context, _app, check_historical_dns, host_domain)',
    ),
    (
        'futures["ioc"] = executor.submit(check_ioc_correlation, host_domain)',
        'futures["ioc"] = executor.submit(_run_in_context, _app, check_ioc_correlation, host_domain)',
    ),
    (
        'futures["query_params"] = executor.submit(analyze_query_params, url_original, host_domain)',
        'futures["query_params"] = executor.submit(_run_in_context, _app, analyze_query_params, url_original, host_domain)',
    ),
    (
        'futures["redirect_chain"] = executor.submit(check_redirect_chain, url, host_domain)',
        'futures["redirect_chain"] = executor.submit(_run_in_context, _app, check_redirect_chain, url, host_domain)',
    ),
    (
        'futures["playwright"] = executor.submit(_run_playwright_checks, url, host_domain)',
        'futures["playwright"] = executor.submit(_run_in_context, _app, _run_playwright_checks, url, host_domain)',
    ),
]

for old, new in submit_replacements:
    if old not in content:
        raise SystemExit(f"Could not find submit call to patch: {old!r}")
    content = content.replace(old, new, 1)

if content == original_content:
    raise SystemExit("No changes were made - something's wrong, aborting without writing.")

with open(PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("app-context fix applied successfully")
