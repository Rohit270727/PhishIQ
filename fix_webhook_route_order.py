"""
fix_webhook_route_order.py
Moves the webhook routes (accidentally appended after app.run()) to
before the `if __name__ == "__main__":` block so Flask actually
registers them.

Run from D:\\PhishIQ with venv active:
    python fix_webhook_route_order.py
"""

from pathlib import Path
import shutil

APP_PY = Path("app.py")
src = APP_PY.read_text(encoding="utf-8")

marker_start = '@app.route("/api/v1/webhooks", methods=["POST"])'
marker_run = 'if __name__ == "__main__":'

if src.count(marker_start) != 1:
    raise SystemExit(f"ABORTED: expected 1 occurrence of route marker, found {src.count(marker_start)}")
if src.count(marker_run) != 1:
    raise SystemExit(f"ABORTED: expected 1 occurrence of __main__ marker, found {src.count(marker_run)}")

start_idx = src.index(marker_start)
run_idx = src.index(marker_run)

if start_idx < run_idx:
    raise SystemExit("Routes already appear before __main__ block — nothing to fix. Check manually.")

# Everything from the route marker to the end of file is the misplaced block
routes_block = src[start_idx:].rstrip("\n") + "\n"

# Remove it from the tail
before_routes = src[:start_idx].rstrip("\n") + "\n"

# Insert it just before the __main__ block, with a blank line separating
run_idx_in_before = before_routes.index(marker_run) if marker_run in before_routes else None
# marker_run should still be present in before_routes since start_idx > run_idx originally... 
# wait: we sliced src[:start_idx], and run_idx < start_idx, so marker_run IS inside before_routes.

new_src = before_routes.replace(
    marker_run,
    routes_block + "\n\n" + marker_run,
    1
)

backup = Path("app.py.bak_routeorder")
shutil.copy(APP_PY, backup)
APP_PY.write_text(new_src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("Moved webhook routes to before the __main__ block.")
print("Verify with: python -c \"import app; print('OK')\"")
print("Then check route registration with the Select-String command below.")