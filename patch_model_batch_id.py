"""
Adds the batch_id field to the AsyncScanJob model class, matching the
column added by migrate_add_batch_id.py.

Run this from the PhishIQ project root, after migrate_add_batch_id.py:
    python patch_model_batch_id.py
"""

PATH = "models.py"

with open(PATH, "r", encoding="utf-8-sig") as f:
    content = f.read()

old = (
    '    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)\n'
    '    url = db.Column(db.Text, nullable=False)\n'
    '    status = db.Column(db.String(20), nullable=False, default="pending")'
)
new = (
    '    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)\n'
    '    url = db.Column(db.Text, nullable=False)\n'
    '    batch_id = db.Column(db.String(36), index=True)  # groups jobs submitted together via the batch API\n'
    '    status = db.Column(db.String(20), nullable=False, default="pending")'
)

if old not in content:
    raise SystemExit("Could not find AsyncScanJob field block - has models.py changed?")

content = content.replace(old, new, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("batch_id field added to AsyncScanJob model")
