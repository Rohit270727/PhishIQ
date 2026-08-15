"""
fix_attack_chain_keywords.py
Adds NXDOMAIN/resolution-failure keywords to the Network & Infrastructure
stage in attack_chain.py, so "does not resolve" / "NXDOMAIN" flags land
in the right bucket instead of falling through to "Other Signals".
"""

from pathlib import Path
import shutil

TARGET = Path("detectors/attack_chain.py")
src = TARGET.read_text(encoding="utf-8")

old = '''    ("Network & Infrastructure", [
        "dns", "asn", "threat intel", "ioc", "shares an ip address",
        "shares", "redirect chain", "hosting", "nameserver", "mx record",
        "query param", "dangling", "historical",
    ]),'''

new = '''    ("Network & Infrastructure", [
        "dns", "asn", "threat intel", "ioc", "shares an ip address",
        "shares", "redirect chain", "hosting", "nameserver", "mx record",
        "query param", "dangling", "historical", "nxdomain", "does not resolve",
        "resolve an ip", "no a record",
    ]),'''

count = src.count(old)
if count != 1:
    raise SystemExit(f"ABORTED: expected 1 match, found {count}. No changes written.")

src = src.replace(old, new, 1)

backup = Path("detectors/attack_chain.py.bak_keywords")
shutil.copy(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("Added NXDOMAIN/resolution-failure keywords to Network & Infrastructure stage.")
print("Verify with: python -c \"from detectors.attack_chain import build_attack_chain; print('OK')\"")