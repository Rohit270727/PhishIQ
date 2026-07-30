path = "models.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    flags = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)"""

new = old + """


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    feedback_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan = db.relationship("ScanHistory", backref=db.backref("feedback_entries", lazy=True, cascade="all, delete-orphan"))"""

if old not in content:
    print("PATTERN NOT FOUND")
else:
    content = content.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("models.py patched")
