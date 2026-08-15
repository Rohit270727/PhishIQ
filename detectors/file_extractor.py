import email
from email import policy
from email.parser import BytesParser
from pypdf import PdfReader


def extract_text_from_file(filepath, ext):
    """Extract plain text from an uploaded .txt, .eml, or .pdf file."""
    ext = ext.lower()

    if ext == "txt":
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    if ext == "eml":
        with open(filepath, "rb") as f:
            raw = f.read()

        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]

        msg = BytesParser(policy=policy.default).parsebytes(raw)

        parts = []

        subject = msg.get("subject", "")
        sender = msg.get("from", "")
        if subject:
            parts.append(f"Subject: {subject}")
        if sender:
            parts.append(f"From: {sender}")

        body = msg.get_body(preferencelist=("plain", "html"))
        if body:
            content = body.get_content()
            parts.append(content)

        return "\n".join(parts)

    if ext == "pdf":
        reader = PdfReader(filepath)
        text_parts = []
        for page in reader.pages:
            text_parts.append(page.extract_text() or "")
        return "\n".join(text_parts)

    raise ValueError(f"Unsupported file type: {ext}")



def extract_sender_domain(filepath, ext):
    """Best-effort extraction of the sender's domain from an uploaded file.
    Only .eml carries real header data; returns None for .txt/.pdf."""
    if ext.lower() != "eml":
        return None

    with open(filepath, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    from_header = msg.get("from", "")
    if not from_header:
        return None

    import re
    match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', str(from_header))
    if match:
        return match.group(1).lower()
    return None


def extract_html_body(filepath, ext):
    """Extract the raw HTML body (if present) from an .eml file, preserving
    tags. Returns None for non-.eml files or messages with no HTML part —
    callers must handle None, not assume a string."""
    if ext.lower() != "eml":
        return None

    with open(filepath, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    html_part = msg.get_body(preferencelist=("html",))
    if html_part is None:
        return None

    try:
        return html_part.get_content()
    except Exception:
        return None
