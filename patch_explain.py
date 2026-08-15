with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

original_len = len(content)

OLD_RESULT = """@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=session["user_id"]).first_or_404()
    flags = json.loads(scan.flags)
    existing_feedback = Feedback.query.filter_by(scan_id=scan.id, user_id=session["user_id"]).first()
    feedback_type = existing_feedback.feedback_type if existing_feedback else None
    return render_template("result.html", scan=scan, flags=flags, feedback_type=feedback_type)"""

NEW_RESULT = """@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=session["user_id"]).first_or_404()
    flags = json.loads(scan.flags)
    existing_feedback = Feedback.query.filter_by(scan_id=scan.id, user_id=session["user_id"]).first()
    feedback_type = existing_feedback.feedback_type if existing_feedback else None

    from detectors.explain import build_signal_breakdown, get_primary_reason, get_confidence
    signal_breakdown, notes = build_signal_breakdown(flags)
    primary_reason = get_primary_reason(flags)
    confidence = get_confidence(flags)

    return render_template(
        "result.html",
        scan=scan,
        flags=flags,
        feedback_type=feedback_type,
        signal_breakdown=signal_breakdown,
        notes=notes,
        primary_reason=primary_reason,
        confidence=confidence,
    )"""

assert OLD_RESULT in content, "result() route anchor not found - aborting, no changes made."
content = content.replace(OLD_RESULT, NEW_RESULT, 1)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(content)

print(f"app.py patched successfully. {original_len} -> {len(content)} chars.")
