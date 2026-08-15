"""
fix_api_key_display.py
Fixes generate_api_key() so the raw key is actually shown once after
creation, instead of being generated, stored, and immediately lost.
"""

from pathlib import Path
import shutil

APP_PY = Path("app.py")
src = APP_PY.read_text(encoding="utf-8")

old = '''    db.session.add(new_key)
    db.session.commit()
    flash("New API key generated. Copy it now - it won't be shown again in full.", "success")
    return redirect(url_for("api_keys"))'''

new = '''    db.session.add(new_key)
    db.session.commit()
    flash(f"New API key generated: {new_key.key} \\u2014 copy it now, it won't be shown again in full.", "success")
    return redirect(url_for("api_keys"))'''

count = src.count(old)
if count != 1:
    raise SystemExit(f"ABORTED: expected 1 match, found {count}")

src = src.replace(old, new, 1)

backup = Path("app.py.bak_apikeydisplay")
shutil.copy(APP_PY, backup)
APP_PY.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("Fixed: raw key now included in the flash message on generation.")
print("Verify with: python -c \"import app; print('OK')\"")