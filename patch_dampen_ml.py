path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """    if ml_scores:
        avg_ml_score = sum(ml_scores) / len(ml_scores)
        if is_trusted:
            final_score = round(0.85 * heuristic_score + 0.15 * avg_ml_score)
            flags.append((f"Registered domain '{registered_domain}' matched trusted allowlist \\u2014 ML score dampened", 0))
        else:
            final_score = round(0.4 * heuristic_score + 0.6 * avg_ml_score)
    else:
        final_score = heuristic_score"""

new = """    has_punycode = any(label.startswith("xn--") for label in domain.split(":")[0].split("."))

    if ml_scores:
        avg_ml_score = sum(ml_scores) / len(ml_scores)
        if is_trusted:
            final_score = round(0.85 * heuristic_score + 0.15 * avg_ml_score)
            flags.append((f"Registered domain '{registered_domain}' matched trusted allowlist \\u2014 ML score dampened", 0))
        elif has_punycode:
            final_score = round(0.75 * heuristic_score + 0.25 * avg_ml_score)
            flags.append(("Internationalized domain \\u2014 character-pattern model dampened (not trained on IDN domains)", 0))
        else:
            final_score = round(0.4 * heuristic_score + 0.6 * avg_ml_score)
    else:
        final_score = heuristic_score"""

if old not in content:
    raise SystemExit("Could not find blend block - aborting, no changes made. Paste current file so I can adjust the match.")
content = content.replace(old, new, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("ML blend now dampened for punycode domains.")
