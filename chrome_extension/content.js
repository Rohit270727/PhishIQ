// content.js
// Injects a dismissible warning banner at the top of the page when
// background.js reports a Dangerous or Suspicious verdict for this tab.
// Runs on every http(s) page (see manifest content_scripts match list).

const BANNER_ID = "phishiq-warning-banner";

function removeBanner() {
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();
}

function showBanner(verdict, score, primaryReason) {
  removeBanner(); // avoid stacking duplicates if messaged twice

  const isDangerous = verdict === "Dangerous";
  const bgColor = isDangerous ? "#ff4757" : "#ffb020";
  const textColor = isDangerous ? "#ffffff" : "#1a1200";
  const label = isDangerous ? "Dangerous site detected" : "Suspicious site detected";

  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${bgColor}; color: ${textColor};
    font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px;
    padding: 10px 16px; display: flex; align-items: center; justify-content: center;
    gap: 14px; box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  `;

  const message = document.createElement("span");
  message.textContent =
    `\u26A0 PhishIQ: ${label} (score ${score}/100)` +
    (primaryReason ? ` \u2014 ${primaryReason}` : "");

  const dismissBtn = document.createElement("button");
  dismissBtn.textContent = "Dismiss";
  dismissBtn.style.cssText = `
    background: rgba(0,0,0,0.15); color: inherit; border: none;
    border-radius: 4px; padding: 4px 10px; font-size: 12px; cursor: pointer;
    flex-shrink: 0;
  `;
  dismissBtn.addEventListener("click", removeBanner);

  banner.appendChild(message);
  banner.appendChild(dismissBtn);
  document.documentElement.appendChild(banner);
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SHOW_BANNER") {
    showBanner(message.verdict, message.score, message.primaryReason);
  } else if (message.type === "CLEAR_BANNER") {
    removeBanner();
  }
});