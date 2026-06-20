/**
 * background.js — PhishGuard Service Worker
 * Intercepts navigation, scans URLs, updates badge.
 */

const API_BASE = "http://localhost:8000";

// Cache to avoid re-scanning same URL
const scanCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// URLs to skip scanning
const SKIP_PATTERNS = [
  /^chrome:/,
  /^chrome-extension:/,
  /^about:/,
  /^moz-extension:/,
  /^file:/,
  /^data:/,
  /localhost/,
  /127\.0\.0\.1/,
];

function shouldSkip(url) {
  return SKIP_PATTERNS.some((p) => p.test(url));
}

// ── Badge helpers ─────────────────────────────────────────────────────────────
function setBadge(tabId, score, classification) {
  const colors = {
    safe:       [39, 174, 96, 255],    // green
    suspicious: [230, 126, 34, 255],   // orange
    phishing:   [231, 76, 60, 255],    // red
  };
  const labels = {
    safe: "",
    suspicious: "!",
    phishing: "!!",
  };

  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: colors[classification] || colors.safe,
  });
  chrome.action.setBadgeText({
    tabId,
    text: labels[classification] || "",
  });
}

// ── Core scan function ────────────────────────────────────────────────────────
async function scanURL(url, tabId) {
  if (shouldSkip(url)) return null;

  // Check cache
  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    applyResult(cached.result, tabId, url);
    return cached.result;
  }

  try {
    const response = await fetch(`${API_BASE}/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error(`API error: ${response.status}`);
    const result = await response.json();

    // Cache it
    scanCache.set(url, { result, timestamp: Date.now() });

    applyResult(result, tabId, url);
    return result;
  } catch (err) {
    console.warn("PhishGuard scan failed:", err.message);
    setBadge(tabId, 0, "safe"); // don't block on API error
    return null;
  }
}

function applyResult(result, tabId, url) {
  // Update badge
  setBadge(tabId, result.risk_score, result.classification);

  // Store latest result for popup
  chrome.storage.local.set({
    [`scan_${tabId}`]: {
      ...result,
      scanned_at: new Date().toISOString(),
    },
  });

  // Show notification for high-risk sites
  if (result.classification === "phishing" && result.risk_score >= 80) {
    chrome.notifications.create(`phish_${tabId}_${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ PhishGuard Warning",
      message: `High-risk website detected! Risk Score: ${result.risk_score}/100`,
      priority: 2,
    });
  }

  // Send result to content script for in-page warning
  if (result.classification === "phishing" && result.risk_score >= 75) {
    chrome.tabs.sendMessage(tabId, {
      type: "SHOW_WARNING",
      result,
    }).catch(() => {}); // tab may not have content script
  }
}

// ── Listen for navigation ─────────────────────────────────────────────────────
chrome.webNavigation.onCompleted.addListener(
  (details) => {
    if (details.frameId !== 0) return; // main frame only
    scanURL(details.url, details.tabId);
  },
  { url: [{ schemes: ["http", "https"] }] }
);

// ── Listen for messages from popup/content ────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    const tabId = sender.tab?.id || message.tabId;
    scanURL(message.url, tabId).then(sendResponse);
    return true; // async
  }

  if (message.type === "SCAN_EMAIL") {
    fetch(`${API_BASE}/scan-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: message.text }),
    })
      .then((r) => r.json())
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === "GET_RESULT") {
    chrome.storage.local.get(`scan_${message.tabId}`, (data) => {
      sendResponse(data[`scan_${message.tabId}`] || null);
    });
    return true;
  }
});

// ── Handle tab switches: reload badge ─────────────────────────────────────────
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.storage.local.get(`scan_${tabId}`, (data) => {
    const result = data[`scan_${tabId}`];
    if (result) {
      setBadge(tabId, result.risk_score, result.classification);
    } else {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  });
});
