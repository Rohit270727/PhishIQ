path = "app.py"
with open(path, encoding="utf-8-sig") as f:
    content = f.read()

old = (
    '        "result.html",\n'
    '        scan=scan,\n'
    '        flags=flags,\n'
    '        feedback_type=feedback_type,\n'
    '        signal_breakdown=signal_breakdown,\n'
    '        notes=notes,\n'
    '        primary_reason=primary_reason,\n'
    '        confidence=confidence,\n'
    '    )\n'
)

new = old.replace(
    '        confidence=confidence,\n    )\n',
    '        confidence=confidence,\n        graph_data=graph_data,\n    )\n'
)

count = content.count(old)
if count != 1:
    print(f"ERROR: anchor text found {count} times, expected exactly 1 - aborting, no changes made")
else:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print("render_template call updated successfully")
