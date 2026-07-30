path = "static/style.css"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

addition = """

/* Feedback section */
.feedback-section {
    margin-top: 24px;
    padding: 20px;
    border: 1px solid #e2e2e2;
    border-radius: 10px;
    background: #fafafa;
}

.feedback-section h2 {
    font-size: 1.1rem;
    margin-bottom: 12px;
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
    border: 1px solid #d0d0d0;
    border-radius: 8px;
    background: #fff;
    cursor: pointer;
    font-size: 0.9rem;
    transition: all 0.15s ease;
}

.feedback-btn:hover {
    border-color: #a0a0a0;
    background: #f0f0f0;
}

.feedback-btn.feedback-correct.active {
    background: #e8f8f2;
    border-color: #00a37a;
    color: #00a37a;
    font-weight: bold;
}

.feedback-btn.feedback-fp.active {
    background: #fdecea;
    border-color: #c0392b;
    color: #c0392b;
    font-weight: bold;
}

.feedback-btn.feedback-fn.active {
    background: #fff8e1;
    border-color: #c98a00;
    color: #c98a00;
    font-weight: bold;
}

.feedback-confirm {
    margin-top: 10px;
    color: #00a37a;
    font-size: 0.9rem;
    font-weight: 500;
}
"""

with open(path, "w", encoding="utf-8") as f:
    f.write(content.rstrip() + "\n" + addition.strip() + "\n")

print("style.css patched")
