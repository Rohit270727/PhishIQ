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

