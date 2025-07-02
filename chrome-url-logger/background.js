chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed");
  sendLog("Extension installed");
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const message = `Tab updated: ${tab.url}`;
    console.log(message);
    sendLog(message, tab.url);
  }
});

function sendLog(message, url = null) {
  const payload = { log: message };
  if (url) {
    payload.url = url;
  }

  fetch('http://localhost:5000/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).catch(err => console.error("Error sending log:", err));
}
