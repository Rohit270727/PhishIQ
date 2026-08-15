import re

path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add the import
old_import = "from detectors.typosquat_detector import check_typosquatting"
new_import = old_import + "\nfrom detectors.homograph_detector import check_homograph"
if old_import not in content:
    raise SystemExit("Could not find typosquat import - aborting, no changes made.")
content = content.replace(old_import, new_import, 1)

# 2. Add the check call right after the typosquat block
anchor = '''    typo_hit = check_typosquatting(domain)
    if typo_hit:
        flags.append((typo_hit["message"], 25))
        score += 25
'''
insertion = anchor + '''
    for hg_message, hg_points in check_homograph(domain):
        flags.append((hg_message, hg_points))
        score += hg_points
'''
if anchor not in content:
    raise SystemExit("Could not find typosquat block anchor - aborting, no changes made.")
content = content.replace(anchor, insertion, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("url_analyzer.py patched successfully.")
