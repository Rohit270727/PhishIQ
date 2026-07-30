path = "templates/admin_dashboard.html"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """<div class="recent-section">
    <div class="section-header"><h2>Top Flagged URLs</h2></div>"""

new = """<div class="recent-section">
    <div class="section-header"><h2>Model Feedback</h2></div>
    {% if feedback_total > 0 %}
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">{{ feedback_total }}</div><div class="stat-label">Total Feedback</div></div>
        <div class="stat-card safe"><div class="stat-value">{{ feedback_correct }}</div><div class="stat-label">Marked Correct</div></div>
        <div class="stat-card dangerous"><div class="stat-value">{{ feedback_fp }}</div><div class="stat-label">False Positives</div></div>
        <div class="stat-card suspicious"><div class="stat-value">{{ feedback_fn }}</div><div class="stat-label">Missed Threats</div></div>
        <div class="stat-card"><div class="stat-value">{{ feedback_accuracy }}%</div><div class="stat-label">Reported Accuracy</div></div>
    </div>
    {% else %}
    <p class="empty-state">No feedback submitted yet.</p>
    {% endif %}
</div>
<div class="recent-section">
    <div class="section-header"><h2>Top Flagged URLs</h2></div>"""

if old not in content:
    print("PATTERN NOT FOUND")
else:
    content = content.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("admin_dashboard.html patched")
