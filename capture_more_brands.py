from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
import json
import os

NEW_SITES = {
    "apple": "https://appleid.apple.com/sign-in",
    "netflix": "https://www.netflix.com/login",
    "instagram": "https://www.instagram.com/accounts/login/",
    "linkedin": "https://www.linkedin.com/login",
}

os.makedirs("reference_screenshots", exist_ok=True)

hashes_path = "detectors/brand_hashes.json"
if os.path.exists(hashes_path):
    with open(hashes_path) as f:
        hashes = json.load(f)
else:
    hashes = {}

with sync_playwright() as p:
    browser = p.chromium.launch()
    for brand, url in NEW_SITES.items():
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, timeout=15000)
            page.wait_for_timeout(2000)
            screenshot_path = f"reference_screenshots/{brand}.png"
            page.screenshot(path=screenshot_path)
            page.close()

            img = Image.open(screenshot_path)
            phash = imagehash.phash(img)
            hashes[brand] = str(phash)
            print(f"{brand}: captured, hash={phash}")
        except Exception as e:
            print(f"{brand}: FAILED - {e}")
    browser.close()

with open(hashes_path, "w") as f:
    json.dump(hashes, f, indent=2)

print("Done. Updated detectors/brand_hashes.json")
