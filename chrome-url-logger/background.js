// background.js - inside chrome-url-logger/
const SERVER_URL = "http://localhost:5000/log";  // your main server.py

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    // Skip internal chrome:// pages
    if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) return;

    fetch(SERVER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        log: `Tab updated: ${tab.url}`,
        level: "INFO",
        source: "chrome-extension",
        url: tab.url,
        title: tab.title || ""
      })
    }).catch(err => console.error("Alertix log error:", err));
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (!tab.url || tab.url.startsWith("chrome://")) return;

    fetch(SERVER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        log: `Tab activated: ${tab.url}`,
        level: "INFO",
        source: "chrome-extension",
        url: tab.url,
        title: tab.title || ""
      })
    }).catch(err => console.error("Alertix log error:", err));
  });
});