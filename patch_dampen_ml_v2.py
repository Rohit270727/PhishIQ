path = "detectors/url_analyzer.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old_flag_def = """    if ml_scores:
        avg_ml_score = sum(ml_scores) / len(ml_scores)"""

new_flag_def = """    has_punycode_flag = any("punycode-encoded" in msg for msg, _ in flags)

    if ml_scores:
        avg_ml_score = sum(ml_scores) / len(ml_scores)"""

if old_flag_def not in content:
    raise SystemExit("Could not find 'if ml_scores:' anchor - aborting, no changes made.")
content = content.replace(old_flag_def, new_flag_def, 1)

old_else = """        else:
            final_score = round(0.4 * heuristic_score + 0.6 * avg_ml_score)"""

new_else = """        elif has_punycode_flag:
            final_score = round(0.75 * heuristic_score + 0.25 * avg_ml_score)
            flags.append(("Internationalized domain - character-pattern model dampened (not trained on IDN domains)", 0))
        else:
            final_score = round(0.4 * heuristic_score + 0.6 * avg_ml_score)"""

if old_else not in content:
    raise SystemExit("Could not find else/blend anchor - aborting, no changes made.")
content = content.replace(old_else, new_else, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Patch applied cleanly (ASCII-only anchors, avoided the mojibake line).")
