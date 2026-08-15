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
