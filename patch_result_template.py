with open("templates/result.html", "r", encoding="utf-8") as f:
    content = f.read()

original_len = len(content)

OLD_HEADER_CLOSE = """        </div>
    </div>

    <div class="flags-section">
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

NEW_HEADER_CLOSE = """        </div>
    </div>

    <div class="explain-section">
        <div class="primary-reason-banner">
            <strong>Primary reason:</strong> {{ primary_reason }}
        </div>
        <div class="confidence-badge confidence-{{ confidence.label|lower }}">
            Model confidence: {{ confidence.label }}
            {% if confidence.raw_percent is not none %}({{ confidence.raw_percent }}%){% endif %}
            <span class="confidence-note" title="This is a bucketed estimate based on distance from the decision boundary, not a calibrated probability.">&#9432;</span>
        </div>
    </div>

    <div class="flags-section">
        <h2>Signal Breakdown</h2>
        {% if signal_breakdown %}
        <ul class="flags-list">
            {% for reason, points in signal_breakdown %}
            <li class="flag-hit">
                <span class="flag-points">+{{ points }}</span>
                <span class="flag-reason">{{ reason }}</span>
            </li>
            {% endfor %}
        </ul>
        {% else %}
        <p class="no-signals">No significant risk signals detected.</p>
        {% endif %}

        {% if notes %}
        <h3 class="notes-heading">Additional Notes</h3>
        <ul class="flags-list flags-notes">
            {% for reason, points in notes %}
            <li class="flag-clean">
                <span class="flag-points">OK</span>
                <span class="flag-reason">{{ reason }}</span>
            </li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>"""

assert OLD_HEADER_CLOSE in content, "flags-section anchor not found - aborting, no changes made."
content = content.replace(OLD_HEADER_CLOSE, NEW_HEADER_CLOSE, 1)

with open("templates/result.html", "w", encoding="utf-8") as f:
    f.write(content)

print(f"result.html patched successfully. {original_len} -> {len(content)} chars.")
