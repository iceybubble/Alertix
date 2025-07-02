const SIEM_ENDPOINT = "http://localhost:5000/log";

function sendLog(message) {
  fetch(SIEM_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      time: new Date().toISOString(),
      log: message,
      category: "Email",
      level: "INFO",
      source: "gmail_extension",
      ip: "127.0.0.1",
      user_agent: navigator.userAgent
    }),
  }).then((response) => {
    if (!response.ok) {
      console.error("Failed to send log:", response.statusText);
    }
  }).catch((error) => {
    console.error("Error sending log:", error);
  });
}

let trackedTabs = {};

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    if (tab.url.includes("mail.google.com")) {
      if (!trackedTabs[tabId]) {
        trackedTabs[tabId] = "gmail";
        sendLog("Gmail web client opened");
      }
    } else if (tab.url.includes("outlook.live.com") || tab.url.includes("office.com")) {
      if (!trackedTabs[tabId]) {
        trackedTabs[tabId] = "outlook";
        sendLog("Outlook web client opened");
      }
    } else {
      if (trackedTabs[tabId]) {
        const app = trackedTabs[tabId];
        delete trackedTabs[tabId];
        sendLog(`${app === "gmail" ? "Gmail" : "Outlook"} web client closed`);
      }
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (trackedTabs[tabId]) {
    const app = trackedTabs[tabId];
    delete trackedTabs[tabId];
    sendLog(`${app === "gmail" ? "Gmail" : "Outlook"} web client closed`);
  }
});
