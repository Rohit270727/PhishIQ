const API_URL = "http://127.0.0.1:5050/api/extension/scan";

let currentTabUrl = "";

document.addEventListener("DOMContentLoaded", () => {
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
});

async function scanCurrentPage() {
  const btn = document.getElementById("scanBtn");
  const errorMsg = document.getElementById("errorMsg");
  const result = document.getElementById("result");

  btn.disabled = true;
  btn.textContent = "Scanning...";
  errorMsg.textContent = "";
  result.style.display = "none";

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentTabUrl })
    });

    if (res.status === 429) {
      throw new Error("Too many scans - please wait a minute and try again.");
    }

    if (!res.ok) {
      throw new Error("Scan failed. Is PhishIQ running on port 5050?");
    }

    const data = await res.json();
    renderResult(data);
  } catch (err) {
    if (err instanceof TypeError) {
      errorMsg.textContent = "Could not reach PhishIQ. Is it running on port 5050?";
    } else {
      errorMsg.textContent = err.message || "Could not reach PhishIQ.";
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan This Page";
  }
}

function renderResult(data) {
  const result = document.getElementById("result");
  const scoreVal = document.getElementById("scoreVal");
  const badge = document.getElementById("verdictBadge");
  const flagsList = document.getElementById("flagsList");

  scoreVal.textContent = data.score;
  badge.textContent = data.verdict;
  badge.className = "badge badge-" + data.verdict.toLowerCase();

  flagsList.innerHTML = "";
  data.flags.forEach(([reason, points]) => {
    const li = document.createElement("li");
    li.textContent = (points > 0 ? "+" + points + " " : "") + reason;
    flagsList.appendChild(li);
  });

  result.style.display = "block";
}


