with open("templates/result.html", encoding="utf-8-sig") as f:
    template_lines = f.readlines()

with open("ioc_graph_section.html", encoding="utf-8-sig") as f:
    graph_snippet = f.read()

# Line 62 (1-indexed) is the closing </div> for flags-section.
# Insert the graph snippet right after it.
insert_after_index = 61  # 0-indexed position of line 62

target_line = template_lines[insert_after_index].strip()
if target_line != "</div>":
    print(f"ERROR: expected line 62 to be '</div>', found '{target_line}' - aborting, no changes made")
else:
    new_lines = (
        template_lines[:insert_after_index + 1]
        + [graph_snippet]
        + template_lines[insert_after_index + 1:]
    )
    with open("templates/result.html", "w", encoding="utf-8", newline="") as f:
        f.writelines(new_lines)
    print("result.html updated successfully")
