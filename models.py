from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32))
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text)  # JSON list of hashed one-time codes
    scans = db.relationship("ScanHistory", backref="user", lazy=True, cascade="all, delete-orphan")

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    label = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime)
    user = db.relationship("User", backref=db.backref("api_keys", lazy=True, cascade="all, delete-orphan"))


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    user = db.relationship("User", backref=db.backref("reset_tokens", lazy=True, cascade="all, delete-orphan"))


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    flags = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    feedback_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan = db.relationship("ScanHistory", backref=db.backref("feedback_entries", lazy=True, cascade="all, delete-orphan"))


class DnsSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    a_records = db.Column(db.Text)   # JSON-serialized list
    ns_records = db.Column(db.Text)  # JSON-serialized list
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)


class IocRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    ip = db.Column(db.String(45), index=True)
    asn = db.Column(db.String(20), index=True)
    asn_description = db.Column(db.String(255))
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
class AsyncScanJob(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID string
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    url = db.Column(db.Text, nullable=False)
    batch_id = db.Column(db.String(36), index=True)  # groups jobs submitted together via the batch API
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending|running|complete|failed
    result = db.Column(db.Text)  # JSON-serialized scan result, set on completion
    error = db.Column(db.Text)   # error message, set on failure
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

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

