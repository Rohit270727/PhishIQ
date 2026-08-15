import re

path = "detectors/homograph_detector.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

anchor = "def check_homograph(domain):"

addition = '''def decode_domain_for_ml(domain):
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


def check_homograph(domain):'''

if anchor not in content:
    raise SystemExit("Could not find check_homograph anchor - aborting, no changes made.")
content = content.replace(anchor, addition, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("decode_domain_for_ml() added to homograph_detector.py")
