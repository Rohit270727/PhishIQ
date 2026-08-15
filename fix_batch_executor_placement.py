"""
Fixes a misplaced line from patch_batch_routes.py: the _batch_executor
assignment landed between the @csrf.exempt and @app.route decorators,
which is invalid syntax (a decorator chain can't have a statement in
the middle of it). This moves it above both decorators instead.

Run this from the PhishIQ project root:
    python fix_batch_executor_placement.py
"""

PATH = "app.py"

with open(PATH, "r", encoding="utf-8") as f:
    content = f.read()

old = (
    "@csrf.exempt\n"
    "_batch_executor = ThreadPoolExecutor(max_workers=5)\n"
    "\n"
    "\n"
    '@app.route("/api/v1/scan/async", methods=["POST"])'
)
new = (
    "_batch_executor = ThreadPoolExecutor(max_workers=5)\n"
    "\n"
    "\n"
    "@csrf.exempt\n"
    '@app.route("/api/v1/scan/async", methods=["POST"])'
)

if old not in content:
    raise SystemExit("Could not find the misplaced block - has app.py changed since the last patch?")

content = content.replace(old, new, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("fixed: _batch_executor moved above the decorators")
