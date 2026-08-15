"""
Adds the WebhookSubscription model to models.py, appended after
AsyncScanJob.

Each subscription belongs to a user, has its own signing secret (used
to HMAC-sign outgoing payloads so receivers can verify authenticity),
and an event_type filter so a user can subscribe to just job
completions, just batch completions, or both.

Run this from the PhishIQ project root:
    python patch_model_webhook.py
"""

PATH = "models.py"

with open(PATH, "r", encoding="utf-8-sig") as f:
    content = f.read()

if "class WebhookSubscription" in content:
    print("WebhookSubscription model already exists - nothing to do")
else:
    addition = '''

class WebhookSubscription(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID string
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    url = db.Column(db.Text, nullable=False)
    secret = db.Column(db.String(64), nullable=False)  # used to HMAC-sign outgoing payloads
    event_type = db.Column(db.String(20), nullable=False, default="all")  # job.complete | batch.complete | all
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_triggered_at = db.Column(db.DateTime)
    last_status_code = db.Column(db.Integer)
    user = db.relationship("User", backref=db.backref("webhooks", lazy=True, cascade="all, delete-orphan"))
'''
    content = content.rstrip("\n") + addition + "\n"

    with open(PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print("WebhookSubscription model added")
