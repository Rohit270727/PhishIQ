"""
fix_webhook_csrf.py
Adds @csrf.exempt above the three webhook routes so Flask-WTF's CSRF
check doesn't block JSON API calls to them.

Run from D:\\PhishIQ with venv active:
    python fix_webhook_csrf.py
"""

from pathlib import Path
import shutil

APP_PY = Path("app.py")
src = APP_PY.read_text(encoding="utf-8")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"ABORTED: expected 1 match for '{label}', found {count}. No changes written.")
    return text.replace(old, new, 1)


targets = [
    ('@app.route("/api/v1/webhooks", methods=["POST"])', "register route"),
    ('@app.route("/api/v1/webhooks", methods=["GET"])', "list route"),
    ('@app.route("/api/v1/webhooks/<webhook_id>", methods=["DELETE"])', "delete route"),
]

for old_line, label in targets:
    new_line = "@csrf.exempt\n" + old_line
    src = replace_once(src, old_line, new_line, label)

backup = Path("app.py.bak_csrf")
shutil.copy(APP_PY, backup)
APP_PY.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("Added @csrf.exempt above all three webhook routes.")
print("Verify with: python -c \"import app; print('OK')\"")