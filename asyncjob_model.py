class AsyncScanJob(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID string
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    url = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending|running|complete|failed
    result = db.Column(db.Text)  # JSON-serialized scan result, set on completion
    error = db.Column(db.Text)   # error message, set on failure
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)