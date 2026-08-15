"""
fix_popup_use_cache.py
Updates popup.js to check for a cached scan result from background.js
first (instant display, no duplicate API call), falling back to a fresh
scan only if nothing is cached yet or the user clicks "Scan This Page" again.
"""

from pathlib import Path
import shutil

POPUP_JS = Path("chrome_extension/popup.js")
src = POPUP_JS.read_text(encoding="utf-8")

old = '''document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    currentTabUrl = tab && tab.url ? tab.url : "";
    const urlBox = document.getElementById("urlBox");

    if (!currentTabUrl || !currentTabUrl.startsWith("http")) {
      urlBox.textContent = "This page cannot be scanned.";
      document.getElementById("scanBtn").disabled = true;
    } else {
      urlBox.textContent = currentTabUrl;
    }
  });

  document.getElementById("scanBtn").addEventListener("click", scanCurrentPage);
});'''

new = '''document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    currentTabUrl = tab && tab.url ? tab.url : "";
    const urlBox = document.getElementById("urlBox");

    if (!currentTabUrl || !currentTabUrl.startsWith("http")) {
      urlBox.textContent = "This page cannot be scanned.";
      document.getElementById("scanBtn").disabled = true;
      return;
    }

    urlBox.textContent = currentTabUrl;

    // Check background.js for an already-cached result for this tab
    // (from auto-scan on page load) before triggering a fresh scan.
    chrome.runtime.sendMessage({ type: "GET_CACHED_RESULT" }, (cached) => {
      if (cached && cached.url === currentTabUrl && cached.result) {
        renderResult(cached.result);
      }
    });
  });

  document.getElementById("scanBtn").addEventListener("click", scanCurrentPage);
});'''

count = src.count(old)
if count != 1:
    raise SystemExit(f"ABORTED: expected 1 match, found {count}. No changes written.")

src = src.replace(old, new, 1)

backup = Path("chrome_extension/popup.js.bak_cache")
shutil.copy(POPUP_JS, backup)
POPUP_JS.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("popup.js now checks background.js cache on open, before falling back to manual scan.")