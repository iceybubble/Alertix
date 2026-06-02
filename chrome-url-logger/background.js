/**
 * Alertix Chrome Extension - background.js
 * ==========================================
 * Service worker that logs every URL the user visits to the
 * Alertix SIEM server (http://127.0.0.1:5000/log).
 *
 * Install:
 *   1. Open chrome://extensions
 *   2. Enable Developer Mode
 *   3. Click "Load unpacked" → select the chrome-url-logger folder
 *   4. Make sure server.py is running on port 5000
 */

const SERVER_URL = "http://127.0.0.1:5000/log";

// ── Skip list: never log these ─────────────────────────────────────────────
const SKIP_PREFIXES = [
  "chrome://",
  "chrome-extension://",
  "about:",
  "data:",
  "javascript:",
  "devtools://",
];

function shouldSkip(url) {
  return SKIP_PREFIXES.some((prefix) => url.startsWith(prefix));
}

// ── Send log to server ──────────────────────────────────────────────────────
async function sendLog(message, level = "INFO", extra = {}) {
  try {
    const response = await fetch(SERVER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        log: message,
        level: level,
        source: "chrome-extension",
        ...extra,
      }),
    });
    if (!response.ok) {
      console.warn(`Alertix server responded ${response.status}`);
    }
  } catch (err) {
    // Server not running or CORS issue
    console.error("Alertix: Failed to send log:", err.message);
  }
}

// ── Tab updated (new page load) ────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only fire once per navigation (when page is fully loaded)
  if (changeInfo.status !== "complete") return;
  if (!tab.url || shouldSkip(tab.url)) return;

  sendLog(
    `Tab updated: ${tab.url}`,
    "INFO",
    { url: tab.url, title: tab.title || "" }
  );
});

// ── Tab activated (user switches to a tab) ─────────────────────────────────
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (chrome.runtime.lastError) return;   // tab may have closed
    if (!tab.url || shouldSkip(tab.url)) return;

    sendLog(
      `Tab activated: ${tab.url}`,
      "INFO",
      { url: tab.url, title: tab.title || "" }
    );
  });
});

// ── Window focus (user comes back to browser) ──────────────────────────────
chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) return;

  chrome.tabs.query({ active: true, windowId }, (tabs) => {
    if (!tabs.length || !tabs[0].url || shouldSkip(tabs[0].url)) return;
    sendLog(
      `Window focus: ${tabs[0].url}`,
      "INFO",
      { url: tabs[0].url, title: tabs[0].title || "" }
    );
  });
});

// ── Startup ping ───────────────────────────────────────────────────────────
chrome.runtime.onStartup.addListener(() => {
  sendLog("Chrome Extension started — Alertix monitoring active", "INFO");
});

chrome.runtime.onInstalled.addListener(() => {
  sendLog("Chrome Extension installed/updated — Alertix monitoring active", "INFO");
});