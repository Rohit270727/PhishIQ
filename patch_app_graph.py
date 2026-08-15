path = "app.py"
with open(path, encoding="utf-8-sig") as f:
    content = f.read()

old = (
    '    from detectors.explain import build_signal_breakdown, get_primary_reason, get_confidence\n'
    '    signal_breakdown, notes = build_signal_breakdown(flags)\n'
    '    primary_reason = get_primary_reason(flags)\n'
    '    confidence = get_confidence(flags)\n'
)

new = old + (
    '\n'
    '    from detectors.ioc_correlation import get_correlation_graph\n'
    '    result_domain = urlparse(scan.input_data if re.match(r"^https?://", scan.input_data, re.IGNORECASE) else "http://" + scan.input_data).netloc.lower()\n'
    '    graph_data = get_correlation_graph(result_domain) if scan.scan_type == "url" else {"nodes": [], "edges": []}\n'
)

count = content.count(old)
if count != 1:
    print(f"ERROR: anchor text found {count} times, expected exactly 1 - aborting, no changes made")
else:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print("app.py updated successfully")
