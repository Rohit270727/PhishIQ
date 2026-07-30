path = "static/style.css"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

marker = "/* Feedback section */"
idx = content.find(marker)

if idx == -1:
    print("MARKER NOT FOUND")
else:
    before = content[:idx]

    new_block = """/* Feedback section */
.feedback-section {
    margin-top: 24px;
    padding: 20px;
    border: 1px solid var(--border-color);
    border-radius: var(--radius);
    background: var(--bg-card);
}
.feedback-section h2 {
    font-size: 18px;
    margin-bottom: 12px;
    color: var(--text-primary);
}
.feedback-buttons {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}
.feedback-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
    font-size: 14px;
    transition: all 0.15s ease;
}
.feedback-btn:hover {
    border-color: var(--accent);
    background: var(--bg-primary);
}
.feedback-btn.feedback-correct.active {
    background: rgba(0,217,163,0.15);
    border-color: var(--safe);
    color: var(--safe);
    font-weight: 700;
}
.feedback-btn.feedback-fp.active {
    background: rgba(255,71,87,0.15);
    border-color: var(--dangerous);
    color: var(--dangerous);
    font-weight: 700;
}
.feedback-btn.feedback-fn.active {
    background: rgba(255,176,32,0.15);
    border-color: var(--suspicious);
    color: var(--suspicious);
    font-weight: 700;
}
.feedback-confirm {
    margin-top: 10px;
    color: var(--safe);
    font-size: 14px;
    font-weight: 500;
}
"""

    new_content = before + new_block
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("style.css re-patched")
