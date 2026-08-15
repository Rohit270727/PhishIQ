import re

path = "test_regression.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

anchor = '    ("http://update-your-icloud-account.click/", "phishing"),\n]'

new_cases = '''    ("http://update-your-icloud-account.click/", "phishing"),

    # Homograph / punycode detection cases
    ("http://xn--pypal-4ve.com/login", "phishing"),        # punycode decodes to a "paypal" look-alike
    ("http://\\u0430pple.com/account", "phishing"),          # raw Cyrillic confusable for apple.com
    ("https://xn--caf-dma.example.com/menu", "legit"),      # real IDN (cafe with accent), not a brand match
]'''

if anchor not in content:
    raise SystemExit("Could not find anchor - aborting, no changes made.")
content = content.replace(anchor, new_cases, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("test_regression.py patched successfully.")
