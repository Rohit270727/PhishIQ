"""
detectors/header_consistency.py
Checks internal consistency of email headers extracted from .eml files.
Pure parsing — reuses the same BytesParser approach as file_extractor.py.
"""
import re
from email import policy
from email.parser import BytesParser


def _extract_domain(header_value: str) -> str | None:
    if not header_value:
        return None
    match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', str(header_value))
    return match.group(1).lower() if match else None


def check_header_consistency(filepath: str) -> list:
    """Returns (message, points) tuples. Only meaningful for .eml files —
    caller should only invoke this when ext == 'eml'."""
    out = []
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return out

    from_domain = _extract_domain(msg.get("from", ""))
    reply_to_domain = _extract_domain(msg.get("reply-to", ""))
    return_path_domain = _extract_domain(msg.get("return-path", ""))

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        out.append((
            f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain}) — replies go somewhere unexpected",
            20
        ))

    if from_domain and return_path_domain and from_domain != return_path_domain:
        out.append((
            f"Return-Path domain ({return_path_domain}) differs from From domain ({from_domain}) — bounce handling doesn't match sender",
            10
        ))

    return out
