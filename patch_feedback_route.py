path = "app.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = "from models import db, User, ScanHistory, ApiKey, PasswordResetToken"
new = "from models import db, User, ScanHistory, ApiKey, PasswordResetToken, Feedback"

if old not in content:
    print("IMPORT PATTERN NOT FOUND")
else:
    content = content.replace(old, new, 1)

anchor = "@app.route(\"/result/<int:scan_id>\")"
if anchor not in content:
    print("ANCHOR NOT FOUND")
else:
    insertion = """@app.route("/scan/<int:scan_id>/feedback", methods=["POST"])
@login_required
def submit_feedback(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=session["user_id"]).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    feedback_type = data.get("feedback_type", "").strip()

    if feedback_type not in ("correct", "false_positive", "false_negative"):
        return jsonify({"error": "Invalid feedback_type"}), 400

    existing = Feedback.query.filter_by(scan_id=scan.id, user_id=session["user_id"]).first()
    if existing:
        existing.feedback_type = feedback_type
        existing.created_at = datetime.utcnow()
    else:
        entry = Feedback(scan_id=scan.id, user_id=session["user_id"], feedback_type=feedback_type)
        db.session.add(entry)

    db.session.commit()
    return jsonify({"success": True, "feedback_type": feedback_type})


"""
    content = content.replace(anchor, insertion + anchor, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("app.py patched")
