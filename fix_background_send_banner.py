"""
fix_background_send_banner.py
Updates background.js's scanAndCache() to message the content script with
SHOW_BANNER (for Dangerous/Suspicious verdicts) or CLEAR_BANNER (for Safe),
right after the badge is set.
"""

from pathlib import Path
import shutil

BG = Path("chrome_extension/background.js")
src = BG.read_text(encoding="utf-8")

old = '''    const data = await res.json();
    tabResults.set(tabId, { url, result: data, scannedAt: Date.now() });
    setBadgeForVerdict(tabId, data.verdict);
  } catch (err) {'''

new = '''    const data = await res.json();
    tabResults.set(tabId, { url, result: data, scannedAt: Date.now() });
    setBadgeForVerdict(tabId, data.verdict);
    notifyContentScript(tabId, data);
  } catch (err) {'''

count = src.count(old)
if count != 1:
    raise SystemExit(f"ABORTED: expected 1 match, found {count}. No changes written.")
src = src.replace(old, new, 1)

# Insert the new helper function right before scanAndCache's definition.
old_fn_start = "async function scanAndCache(tabId, url) {"
new_fn_start = '''function notifyContentScript(tabId, data) {
  if (data.verdict === "Dangerous" || data.verdict === "Suspicious") {
    const scored = (data.flags || []).filter(([, points]) => points > 0);
    const top = scored.length
      ? scored.reduce((a, b) => (b[1] > a[1] ? b : a))
      : null;
    const primaryReason = top ? top[0] : null;

    chrome.tabs.sendMessage(
      tabId,
      { type: "SHOW_BANNER", verdict: data.verdict, score: data.score, primaryReason },
      () => {
        // Swallow "no receiving end" errors - happens on chrome:// pages,
        // extension pages, or tabs where the content script hasn't loaded yet.
        void chrome.runtime.lastError;
      }
    );
  } else {
    chrome.tabs.sendMessage(tabId, { type: "CLEAR_BANNER" }, () => {
      void chrome.runtime.lastError;
    });
  }
}

async function scanAndCache(tabId, url) {'''

count2 = src.count(old_fn_start)
if count2 != 1:
    raise SystemExit(f"ABORTED: expected 1 match for function anchor, found {count2}. No changes written.")
src = src.replace(old_fn_start, new_fn_start, 1)

backup = Path("chrome_extension/background.js.bak_banner")
shutil.copy(BG, backup)
BG.write_text(src, encoding="utf-8")

print(f"Backed up -> {backup}")
print("background.js now sends SHOW_BANNER/CLEAR_BANNER to content.js after each scan.")