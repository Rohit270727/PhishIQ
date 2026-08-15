"""
fix_attack_chain_template.py
Inserts the attack-chain visualization section into result.html,
right before the existing explain-section (primary reason / confidence).
"""

from pathlib import Path
import shutil

TEMPLATE = Path("templates/result.html")
src = TEMPLATE.read_text(encoding="utf-8")

old = '''    <div class="explain-section">'''

new = '''    {% if chain_data %}
    <div class="flags-section" id="attack-chain-section">
        <h2>Attack Chain</h2>
        <p class="page-subtitle" style="margin-bottom:16px;">The sequence of checks that ran during this scan, in order, with how each stage moved the score.</p>
        <div class="attack-chain" style="display:flex; flex-direction:column; gap:0;">
            {% for stage in chain_data %}
            <div class="chain-stage" style="border:1px solid var(--border-color); border-radius:8px; padding:14px 16px; margin-bottom:{{ '0' if loop.last else '8px' }}; background:var(--bg-primary);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <strong>{{ loop.index }}. {{ stage.stage }}</strong>
                    <span class="flag-points" style="font-weight:600;">
                        {{ '+' if stage.stage_points >= 0 else '' }}{{ stage.stage_points }} pts
                        <span style="opacity:0.6; font-weight:400;">&rarr; running total: {{ stage.running_total }}</span>
                    </span>
                </div>
                <ul class="flags-list" style="margin:0;">
                    {% for signal in stage.signals %}
                    <li class="flag-hit">
                        <span class="flag-points">{{ '+' if signal.points >= 0 else '' }}{{ signal.points }}</span>
                        {{ signal.reason }}
                    </li>
                    {% endfor %}
                </ul>
            </div>
            {% if not loop.last %}
            <div style="text-align:center; opacity:0.4; font-size:1.2em; margin:2px 0;">&darr;</div>
            {% endif %}
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <div class="explain-section">'''

count = src.count(old)
if count != 1:
    raise SystemExit(f"ABORTED: expected 1 match, found {count}. No changes written.")

src = src.replace(old, new, 1)

backup = Path("templates/result.html.bak_attackchain")
shutil.copy(TEMPLATE, backup)
TEMPLATE.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("Inserted attack-chain section into result.html.")