"""
fix_manifest_content_script.py
Expands host_permissions to all http/https sites and registers content.js
as a content script, so the warning banner can be injected on any page.
"""

from pathlib import Path
import shutil
import json

MANIFEST = Path("chrome_extension/manifest.json")
data = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))

# Keep the local API host permission, add broad http/https for content script injection.
host_perms = set(data.get("host_permissions", []))
host_perms.update(["http://*/*", "https://*/*"])
data["host_permissions"] = sorted(host_perms)

data["content_scripts"] = [
    {
        "matches": ["http://*/*", "https://*/*"],
        "js": ["content.js"],
        "run_at": "document_idle"
    }
]

backup = Path("chrome_extension/manifest.json.bak_contentscript")
shutil.copy(MANIFEST, backup)
MANIFEST.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

print(f"Backed up -> {backup}")
print("Added content_scripts entry + expanded host_permissions.")
print(json.dumps(data, indent=2))