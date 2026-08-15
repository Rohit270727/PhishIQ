"""
fix_manifest_background.py
Adds background service worker + tabs/scripting permissions to manifest.json
for auto-scan badge icon support. Handles UTF-8 BOM if present.
"""

from pathlib import Path
import shutil
import json

MANIFEST = Path("chrome_extension/manifest.json")
data = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))

data["background"] = {"service_worker": "background.js"}

existing_perms = set(data.get("permissions", []))
existing_perms.update(["tabs", "scripting", "storage"])
data["permissions"] = sorted(existing_perms)

backup = Path("chrome_extension/manifest.json.bak_background")
shutil.copy(MANIFEST, backup)
MANIFEST.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

print(f"Backed up -> {backup}")
print("Added background service worker + tabs/scripting/storage permissions.")
print(json.dumps(data, indent=2))