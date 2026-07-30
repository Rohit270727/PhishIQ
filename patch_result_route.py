path = "app.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=session["user_id"]).first_or_404()
    flags = json.loads(scan.flags)
    return render_template("result.html", scan=scan, flags=flags)"""

new = """@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=session["user_id"]).first_or_404()
    flags = json.loads(scan.flags)
    existing_feedback = Feedback.query.filter_by(scan_id=scan.id, user_id=session["user_id"]).first()
    feedback_type = existing_feedback.feedback_type if existing_feedback else None
    return render_template("result.html", scan=scan, flags=flags, feedback_type=feedback_type)"""

if old not in content:
    print("PATTERN NOT FOUND")
else:
    content = content.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("result() route patched")
