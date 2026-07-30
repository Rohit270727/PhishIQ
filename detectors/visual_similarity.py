import json
import os
from playwright.sync_api import sync_playwright
from PIL import Image
import imagehash

HASHES_PATH = os.path.join(os.path.dirname(__file__), "brand_hashes.json")

with open(HASHES_PATH) as f:
    BRAND_HASHES = json.load(f)

SIMILARITY_THRESHOLD = 10  # lower = stricter match; phash hamming distance

def check_visual_similarity(url, domain):
    """
    Screenshot the target URL and compare visually against known brand login pages.
    Returns a flag dict if the page closely resembles a brand it isn't actually from.
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, timeout=10000)
            page.wait_for_timeout(1500)
            screenshot_path = "temp_scan_screenshot.png"
            page.screenshot(path=screenshot_path)
            page.close()
            browser.close()

        img = Image.open(screenshot_path)
        target_hash = imagehash.phash(img)

        os.remove(screenshot_path)

        best_match = None
        best_distance = None

        for brand, hash_str in BRAND_HASHES.items():
            brand_hash = imagehash.hex_to_hash(hash_str)
            distance = target_hash - brand_hash

            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_match = brand

        if best_match and best_distance is not None and best_distance <= SIMILARITY_THRESHOLD:
            if best_match not in domain:
                return {
                    "brand": best_match,
                    "distance": best_distance,
                    "message": f"Page visually resembles '{best_match}' login page but domain does not match - possible visual spoofing"
                }

        return None

    except Exception:
        return None
