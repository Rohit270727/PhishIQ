path = "app.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """    recent_scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(20).all()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_scans=total_scans,
        dangerous_count=dangerous_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        top_domains=top_domains,
        recent_scans=recent_scans
    )"""

new = """    recent_scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(20).all()

    feedback_correct = Feedback.query.filter_by(feedback_type="correct").count()
    feedback_fp = Feedback.query.filter_by(feedback_type="false_positive").count()
    feedback_fn = Feedback.query.filter_by(feedback_type="false_negative").count()
    feedback_total = feedback_correct + feedback_fp + feedback_fn
    feedback_accuracy = round((feedback_correct / feedback_total) * 100, 1) if feedback_total > 0 else None

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_scans=total_scans,
        dangerous_count=dangerous_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        top_domains=top_domains,
        recent_scans=recent_scans,
        feedback_correct=feedback_correct,
        feedback_fp=feedback_fp,
        feedback_fn=feedback_fn,
        feedback_total=feedback_total,
        feedback_accuracy=feedback_accuracy
    )"""

if old not in content:
    print("PATTERN NOT FOUND")
else:
    content = content.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("admin_dashboard route patched")
