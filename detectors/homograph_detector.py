import codecs
from detectors.typosquat_detector import KNOWN_BRANDS, levenshtein

# Characters that visually resemble ASCII letters, mapped to their look-alike.
# Covers the Cyrillic and Greek letters most commonly abused in homograph attacks.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ѡ": "w", "ⅼ": "l",
    "к": "k", "м": "m", "т": "t", "в": "b", "г": "r", "ѵ": "v", "ⅰ": "i",
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "κ": "k", "ν": "v", "τ": "t",
    "ι": "i", "β": "b", "η": "n",
}

def _normalize_confusables(text):
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)

def _decode_punycode_label(label):
    if not label.startswith("xn--"):
        return None
    try:
        return codecs.decode(label[4:], "punycode")
    except Exception:
        return None

def _check_label_for_brand(label):
    """Given a (possibly decoded) label, see if its confusable-normalized
    form matches a known brand closely enough to be an impersonation."""
    normalized = _normalize_confusables(label).lower()
    if normalized == label.lower():
        return None  # no non-ASCII substitution happened, nothing to flag here
    for brand in KNOWN_BRANDS:
        dist = levenshtein(normalized, brand)
        if dist <= 1 and len(normalized) >= 4:
            return brand, dist
    return None

def decode_domain_for_ml(domain):
    """Return the domain with any punycode labels decoded to their
    Unicode form, for feeding to ML models that were never trained on
    raw ACE-encoded (xn--) strings. Falls back to the original label
    if decoding fails. Does not touch non-punycode labels."""
    core = domain.split(":")[0]
    labels = core.split(".")
    decoded_labels = []
    for label in labels:
        decoded = _decode_punycode_label(label)
        decoded_labels.append(decoded if decoded is not None else label)
    return ".".join(decoded_labels)


def check_homograph(domain):
    """Returns a list of (message, points) tuples - zero, one, or two
    findings (punycode presence and/or brand-impersonation match)."""
    findings = []
    core = domain.split(":")[0]
    labels = core.split(".")

    for label in labels:
        decoded = _decode_punycode_label(label)
        if decoded is not None:
            findings.append((
                f"Domain label '{label}' is punycode-encoded (decodes to '{decoded}') "
                "- possible internationalized-domain homograph attack",
                10
            ))
            hit = _check_label_for_brand(decoded)
            if hit:
                brand, dist = hit
                findings.append((
                    f"Decoded domain closely resembles brand '{brand}' using look-alike "
                    f"characters (edit distance {dist}) - likely homograph impersonation",
                    30
                ))
        else:
            # Raw (non-punycode) label - check directly for confusable substitution
            hit = _check_label_for_brand(label)
            if hit:
                brand, dist = hit
                findings.append((
                    f"Domain label '{label}' uses look-alike Unicode characters resembling "
                    f"brand '{brand}' (edit distance {dist}) - possible homograph impersonation",
                    30
                ))

    return findings
