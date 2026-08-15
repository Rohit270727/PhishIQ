// background.js
// Auto-scans the active tab's URL when navigation completes, caches the
// result per tab, and sets a colored badge on the toolbar icon so risk
// is visible at a glance without opening the popup.

const API_URL = "http://127.0.0.1:5050/api/extension/scan";
const RESCAN_COOLDOWN_MS = 3 * 60 * 1000; // 3 min - avoids hammering the
// 10/min rate limit if a user revisits the same tab/URL repeatedly.

// In-memory cache: tabId -> { url, result, scannedAt }
// Cleared automatically when a tab closes or navigates to a new URL.
const tabResults = new Map();

function isScannableUrl(url) {
  return typeof url === "string" && url.startsWith("http");
}

function setBadgeForVerdict(tabId, verdict) {
  const badgeConfig = {
    Safe: { text: "OK", color: "#00d9a3" },
    Suspicious: { text: "!", color: "#ffb020" },
    Dangerous: { text: "X", color: "#ff4757" },
  };
  const cfg = badgeConfig[verdict] || { text: "", color: "#8a94a8" };
  chrome.action.setBadgeText({ tabId, text: cfg.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: "" });
}

function notifyContentScript(tabId, data) {
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

async function scanAndCache(tabId, url) {
  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) {
      // Rate-limited, server down, etc. - fail silently on the badge,
      // popup will show the real error if the user opens it and clicks Scan.
      clearBadge(tabId);
      return;
    }

    const data = await res.json();
    tabResults.set(tabId, { url, result: data, scannedAt: Date.now() });
    setBadgeForVerdict(tabId, data.verdict);
    notifyContentScript(tabId, data);
  } catch (err) {
    // PhishIQ likely not running locally - stay silent, don't spam badge errors.
    clearBadge(tabId);
  }
}

function maybeScan(tabId, url) {
  if (!isScannableUrl(url)) {
    clearBadge(tabId);
    tabResults.delete(tabId);
    return;
  }

  const cached = tabResults.get(tabId);
  const isSameUrl = cached && cached.url === url;
  const isFresh = cached && Date.now() - cached.scannedAt < RESCAN_COOLDOWN_MS;

  if (isSameUrl && isFresh) {
    setBadgeForVerdict(tabId, cached.result.verdict);
    return;
  }

  scanAndCache(tabId, url);
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only act once the page has actually finished loading and has a URL -
  // avoids firing multiple scans per navigation (loading -> complete).
  if (changeInfo.status === "complete" && tab.url) {
    maybeScan(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;
    maybeScan(tabId, tab.url);
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

// Exposed for popup.js to read the cached result instead of re-scanning.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_CACHED_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      const cached = tab ? tabResults.get(tab.id) : null;
      sendResponse(cached || null);
    });
    return true; // keep the message channel open for async sendResponse
  }
});