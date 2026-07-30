path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """    for brand in BRAND_NAMES:
        if brand in domain and domain != brand + ".com" and not domain.endswith("." + brand + ".com"):
            flags.append((f"Possible brand impersonation of '{brand}' in domain", 20))
            score += 20
            break"""

new = """    if not is_trusted:
        for brand in BRAND_NAMES:
            if brand in domain and domain != brand + ".com" and not domain.endswith("." + brand + ".com"):
                flags.append((f"Possible brand impersonation of '{brand}' in domain", 20))
                score += 20
                break"""

if old not in content:
    print("PATTERN NOT FOUND -- aborting, no changes made")
else:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Patched successfully")
