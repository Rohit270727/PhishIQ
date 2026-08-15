"""
fix_attack_chain_route.py
Wires build_attack_chain() into the result() route so result.html
receives chain_data alongside the existing signal_breakdown/graph_data.
"""

from pathlib import Path
import shutil

APP_PY = Path("app.py")
src = APP_PY.read_text(encoding="utf-8")

old = '''    from detectors.ioc_correlation import get_correlation_graph
    result_domain = urlparse(scan.input_data if re.match(r"^https?://", scan.input_data, re.IGNORECASE) else "http://" + scan.input_data).netloc.lower()
    graph_data = get_correlation_graph(result_domain) if scan.scan_type == "url" else {"nodes": [], "edges": []}

    return render_template(
        "result.html",
        scan=scan,
        flags=flags,
        feedback_type=feedback_type,
        signal_breakdown=signal_breakdown,
        notes=notes,
        primary_reason=primary_reason,
        confidence=confidence,
        graph_data=graph_data,
    )'''

new = '''    from detectors.ioc_correlation import get_correlation_graph
    result_domain = urlparse(scan.input_data if re.match(r"^https?://", scan.input_data, re.IGNORECASE) else "http://" + scan.input_data).netloc.lower()
    graph_data = get_correlation_graph(result_domain) if scan.scan_type == "url" else {"nodes": [], "edges": []}

    from detectors.attack_chain import build_attack_chain
    chain_data = build_attack_chain(flags)

    return render_template(
        "result.html",
        scan=scan,
        flags=flags,
        feedback_type=feedback_type,
        signal_breakdown=signal_breakdown,
        notes=notes,
        primary_reason=primary_reason,
        confidence=confidence,
        graph_data=graph_data,
        chain_data=chain_data,
    )'''

count = src.count(old)
if count != 1:
    raise SystemExit(f"ABORTED: expected 1 match, found {count}. No changes written.")

src = src.replace(old, new, 1)

backup = Path("app.py.bak_attackchain")
shutil.copy(APP_PY, backup)
APP_PY.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("Wired build_attack_chain() into result() route.")
print("Verify with: python -c \"import app; print('OK')\"")