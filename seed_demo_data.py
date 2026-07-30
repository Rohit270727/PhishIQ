from datetime import datetime, timedelta
import json
import random

from app import app
from models import db, User, ScanHistory
from werkzeug.security import generate_password_hash

DEMO_USERNAME = "demo"
DEMO_EMAIL = "demo@phishiq.local"
DEMO_PASSWORD = "demo1234"

SAMPLE_SCANS = [
    {
        "scan_type": "url",
        "input_data": "https://github.com",
        "risk_score": 0,
        "verdict": "Safe",
        "flags": [["ML model confidence: 0% phishing probability", 0]],
    },
    {
        "scan_type": "url",
        "input_data": "https://accounts.google.com/signin",
        "risk_score": 5,
        "verdict": "Safe",
        "flags": [["ML model confidence: 5% phishing probability", 0]],
    },
    {
        "scan_type": "url",
        "input_data": "http://paypa1-secure.tk/login",
        "risk_score": 88,
        "verdict": "Dangerous",
        "flags": [
            ["Connection is not secured with HTTPS", 15],
            ["Domain uses a high-risk TLD (.tk)", 15],
            ["Domain 'paypa1' closely resembles brand 'paypal' (edit distance 1) - possible typosquatting", 25],
            ["Contains suspicious keyword(s): login, secure", 14],
            ["ML model confidence: 78% phishing probability", 0],
        ],
    },
    {
        "scan_type": "url",
        "input_data": "http://amaz0n-account-verify.xyz/update",
        "risk_score": 74,
        "verdict": "Dangerous",
        "flags": [
            ["Connection is not secured with HTTPS", 15],
            ["Domain uses a high-risk TLD (.xyz)", 15],
            ["Contains suspicious keyword(s): verify, update, account", 20],
            ["Domain registered very recently (4 days ago)", 20],
        ],
    },
    {
        "scan_type": "url",
        "input_data": "http://bit.ly/3xK9pLm",
        "risk_score": 45,
        "verdict": "Suspicious",
        "flags": [
            ["Connection is not secured with HTTPS", 15],
            ["Uses a URL shortening service (bit.ly)", 15],
            ["ML model confidence: 30% phishing probability", 0],
        ],
    },
    {
        "scan_type": "message",
        "input_data": "URGENT: Your bank account has been suspended. Verify immediately at http://secure-bankalert.tk/verify or lose access permanently.",
        "risk_score": 82,
        "verdict": "Dangerous",
        "flags": [
            ["Creates false urgency: 'urgent'", 10],
            ["Contains 1 embedded link(s)", 15],
            ["ML model confidence: 85% scam probability", 0],
        ],
    },
    {
        "scan_type": "message",
        "input_data": "Hey, are we still on for lunch tomorrow at 1pm?",
        "risk_score": 2,
        "verdict": "Safe",
        "flags": [["No known phishing indicators detected", 0]],
    },
    {
        "scan_type": "message",
        "input_data": "Congratulations! You've won a $500 gift card. Claim now: http://giftclaim-reward.win/claim",
        "risk_score": 68,
        "verdict": "Dangerous",
        "flags": [
            ["Contains 1 embedded link(s)", 15],
            ["Domain uses a high-risk TLD (.win)", 15],
            ["ML model confidence: 70% scam probability", 0],
        ],
    },
    {
        "scan_type": "qr",
        "input_data": "http://paypa1-secure.tk/login",
        "risk_score": 88,
        "verdict": "Dangerous",
        "flags": [
            ["Domain 'paypa1' closely resembles brand 'paypal' (edit distance 1) - possible typosquatting", 25],
            ["Domain uses a high-risk TLD (.tk)", 15],
        ],
    },
    {
        "scan_type": "url",
        "input_data": "https://www.amazon.com/ap/signin",
        "risk_score": 0,
        "verdict": "Safe",
        "flags": [["ML model confidence: 0% phishing probability", 0]],
    },
]


def seed():
    with app.app_context():
        user = User.query.filter_by(username=DEMO_USERNAME).first()
        if not user:
            user = User(
                username=DEMO_USERNAME,
                email=DEMO_EMAIL,
                password_hash=generate_password_hash(DEMO_PASSWORD),
            )
            db.session.add(user)
            db.session.commit()
            print(f"Created demo user '{DEMO_USERNAME}' (password: {DEMO_PASSWORD})")
        else:
            print(f"Demo user '{DEMO_USERNAME}' already exists")

        existing_count = ScanHistory.query.filter_by(user_id=user.id).count()
        if existing_count > 0:
            print(f"Demo user already has {existing_count} scans - skipping seed to avoid duplicates")
            return

        now = datetime.utcnow()
        for i, scan_data in enumerate(SAMPLE_SCANS):
            days_ago = random.randint(0, 6)
            hours_ago = random.randint(0, 23)
            created_at = now - timedelta(days=days_ago, hours=hours_ago)

            scan = ScanHistory(
                user_id=user.id,
                scan_type=scan_data["scan_type"],
                input_data=scan_data["input_data"],
                risk_score=scan_data["risk_score"],
                verdict=scan_data["verdict"],
                flags=json.dumps(scan_data["flags"]),
                created_at=created_at,
            )
            db.session.add(scan)

        db.session.commit()
        print(f"Seeded {len(SAMPLE_SCANS)} demo scans for '{DEMO_USERNAME}'")


if __name__ == "__main__":
    seed()
