import re

path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = '''    if domain.count("-") >= 2:
        flags.append(("Multiple hyphens in domain name", 8))
        score += 8
'''

new = '''    if domain.count("-") >= 2 and not any(label.startswith("xn--") for label in domain.split(".")):
        flags.append(("Multiple hyphens in domain name", 8))
        score += 8
'''

if old not in content:
    raise SystemExit("Could not find hyphen-check block - aborting, no changes made.")
content = content.replace(old, new, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Hyphen check patched to exempt punycode labels.")
