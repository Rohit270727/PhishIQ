content = open("detectors/url_analyzer.py", encoding="utf-8").read()

old = """    for s in SHORTENERS:
        if s in domain:
            flags.append((f"Uses a URL shortening service ({s})", 15))
            score += 15
            break"""

new = """    for s in SHORTENERS:
        # Match the shortener as the actual registered domain, not as a
        # substring anywhere in the host (e.g. "t.co" inside "microsoft.com").
        if domain == s or domain.endswith("." + s):
            flags.append((f"Uses a URL shortening service ({s})", 15))
            score += 15
            break"""

assert old in content, "shortener block not found — aborting"
content = content.replace(old, new, 1)
open("detectors/url_analyzer.py", "w", encoding="utf-8").write(content)
print("url_analyzer.py patched — shortener substring bug fixed")
