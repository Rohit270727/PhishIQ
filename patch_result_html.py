path = "templates/result.html"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

anchor = """    <div class="flags-section">
        <h2>Detection Breakdown</h2>
        <ul class="flags-list">
            {% for reason, points in flags %}
            <li class="{{ 'flag-clean' if points == 0 else 'flag-hit' }}">
                <span class="flag-points">{{ '+' ~ points if points > 0 else 'OK' }}</span>
                <span class="flag-reason">{{ reason }}</span>
            </li>
            {% endfor %}
        </ul>
    </div>"""

if anchor not in content:
    print("ANCHOR NOT FOUND")
else:
    insertion = """

    <div class="feedback-section">
        <h2>Was this result accurate?</h2>
        <div class="feedback-buttons" data-scan-id="{{ scan.id }}">
            <button type="button" class="feedback-btn feedback-correct {{ 'active' if feedback_type == 'correct' else '' }}" data-type="correct">
                &#128077; Correct
            </button>
            <button type="button" class="feedback-btn feedback-fp {{ 'active' if feedback_type == 'false_positive' else '' }}" data-type="false_positive">
                &#128078; False Positive
            </button>
            <button type="button" class="feedback-btn feedback-fn {{ 'active' if feedback_type == 'false_negative' else '' }}" data-type="false_negative">
                &#9888; Missed Threat
            </button>
        </div>
        <p class="feedback-confirm" style="display:none;">Thanks for the feedback!</p>
    </div>"""
    content = content.replace(anchor, anchor + insertion, 1)

script = """
{% block scripts %}
<script>
document.addEventListener("DOMContentLoaded", function () {
    const container = document.querySelector(".feedback-buttons");
    if (!container) return;

    const scanId = container.dataset.scanId;
    const confirmMsg = document.querySelector(".feedback-confirm");

    container.querySelectorAll(".feedback-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            const feedbackType = btn.dataset.type;

            fetch(`/scan/${scanId}/feedback`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": "{{ csrf_token() }}"
                },
                body: JSON.stringify({ feedback_type: feedbackType })
            })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (data.success) {
                    container.querySelectorAll(".feedback-btn").forEach(function (b) {
                        b.classList.remove("active");
                    });
                    btn.classList.add("active");
                    if (confirmMsg) {
                        confirmMsg.style.display = "block";
                        setTimeout(function () { confirmMsg.style.display = "none"; }, 2500);
                    }
                } else {
                    alert(data.error || "Could not save feedback.");
                }
            })
            .catch(function () {
                alert("Network error saving feedback.");
            });
        });
    });
});
</script>
{% endblock %}
"""

if "{% endblock %}" in content and "{% block scripts %}" not in content:
    content = content.rstrip() + "\n" + script.strip() + "\n"

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("result.html patched")
