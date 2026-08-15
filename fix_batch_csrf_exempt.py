"""
Adds the missing @csrf.exempt decorator to POST /api/v1/scan/batch.
This route was missed when patch_batch_routes.py was written - the
existing POST /api/v1/scan/async route has @csrf.exempt since it's a
JSON API endpoint, not a browser form submission, and the batch route
needs the same treatment.

Run this from the PhishIQ project root:
    python fix_batch_csrf_exempt.py
"""

PATH = "app.py"

with open(PATH, "r", encoding="utf-8") as f:
    content = f.read()

old = (
    '@app.route("/api/v1/scan/batch", methods=["POST"])\n'
    '@limiter.limit("10 per minute")\n'
    "@require_api_key\n"
)
new = (
    "@csrf.exempt\n"
    '@app.route("/api/v1/scan/batch", methods=["POST"])\n'
    '@limiter.limit("10 per minute")\n'
    "@require_api_key\n"
)

if old not in content:
    raise SystemExit("Could not find the batch route decorators - has app.py changed?")

content = content.replace(old, new, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("fixed: @csrf.exempt added to /api/v1/scan/batch")
