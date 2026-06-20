/**
 * popup.js — PhishGuard Popup Logic
 */

const API_BASE = "http://localhost:8000";

// ── Utility ───────────────────────────────────────────────────────────────────
function getClassificationColor(cls) {
  return { safe: "#27ae60", suspicious: "#e67e22", phishing: "#e74c3c" }[cls] || "#27ae60";
}

function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ── Render URL result ─────────────────────────────────────────────────────────
function renderURLResult(result) {
  document.getElementById("loading-state").style.display = "none";
  document.getElementById("error-state").style.display   = "none";
  document.getElementById("result-state").style.display  = "block";

  const { risk_score, classification, reasons, brand_impersonation, scanned_at } = result;
  const color = getClassificationColor(classification);

  // Badge
  const badge    = document.getElementById("risk-badge");
  const badgeMap = {
    safe:       { text: "Safe",       icon: "✓",  cls: "safe"       },
    suspicious: { text: "Suspicious", icon: "!",  cls: "suspicious" },
    phishing:   { text: "Phishing",   icon: "⚠", cls: "phishing"   },
  };
  const b = badgeMap[classification] || badgeMap.safe;
  badge.className = `risk-badge ${b.cls}`;
  document.getElementById("badge-icon").textContent = b.icon;
  document.getElementById("badge-text").textContent = b.text;

  // Score ring
  const circle        = document.getElementById("score-circle");
  const circumference = 295.31;
  const offset        = circumference - (risk_score / 100) * circumference;
  circle.style.strokeDashoffset = offset;
  circle.style.stroke           = color;

  document.getElementById("score-number").textContent = risk_score;
  document.getElementById("score-number").style.color = color;

  // URL
  const urlEl = document.getElementById("current-url");
  urlEl.textContent = result.url || window.location.href;

  // Brand impersonation
  const brandSection = document.getElementById("brand-section");
  if (brand_impersonation) {
    brandSection.style.display = "block";
    document.getElementById("brand-name").textContent =
      `Likely target: ${brand_impersonation.brand}`;
    document.getElementById("brand-score-text").textContent =
      `Similarity score: ${brand_impersonation.similarity_score}%`;
  } else {
    brandSection.style.display = "none";
  }

  // Reasons
  const section = document.getElementById("reasons-section");
  section.innerHTML = "";

  if (reasons && reasons.length > 0) {
    const title = document.createElement("div");
    title.className   = "reasons-title";
    title.textContent = classification === "safe" ? "Analysis" : "Risk Factors";
    section.appendChild(title);

    reasons.forEach((r) => {
      const item = document.createElement("div");
      item.className = `reason-item ${classification}`;
      item.innerHTML = `
        <span class="reason-icon">${classification === "safe" ? "✓" : "⚠"}</span>
        <span>${r}</span>
      `;
      section.appendChild(item);
    });
  }

  // Footer time
  document.getElementById("scanned-at").textContent =
    scanned_at ? `Scanned at ${formatTime(scanned_at)}` : "";
}

// ── API status check ──────────────────────────────────────────────────────────
async function checkAPIStatus() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      document.getElementById("status-dot").classList.remove("offline");
      document.getElementById("status-text").textContent = "Active";
      document.getElementById("status-text").style.color = "#27ae60";
      return true;
    }
  } catch (_) {}
  document.getElementById("status-dot").classList.add("offline");
  document.getElementById("status-text").textContent = "Offline";
  document.getElementById("status-text").style.color = "#e74c3c";
  return false;
}

// ── Load current tab result ───────────────────────────────────────────────────
async function loadCurrentTabResult() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    document.getElementById("loading-state").style.display = "none";
    document.getElementById("error-state").style.display   = "block";
    return;
  }

  // Show URL immediately
  document.getElementById("loading-state").style.display = "flex";

  // Try to get cached result first
  const cached = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, resolve);
  });

  if (cached) {
    renderURLResult(cached);
    return;
  }

  // Otherwise trigger a fresh scan
  const apiOk = await checkAPIStatus();
  if (!apiOk) {
    document.getElementById("loading-state").style.display = "none";
    document.getElementById("error-state").style.display   = "block";
    return;
  }

  chrome.runtime.sendMessage(
    { type: "SCAN_URL", url: tab.url, tabId: tab.id },
    (result) => {
      if (chrome.runtime.lastError || !result) {
        document.getElementById("loading-state").style.display = "none";
        document.getElementById("error-state").style.display   = "block";
        return;
      }
      result.scanned_at = new Date().toISOString();
      renderURLResult(result);
    }
  );
}

// ── Email scan ────────────────────────────────────────────────────────────────
document.getElementById("scan-email-btn").addEventListener("click", async () => {
  const text = document.getElementById("email-input").value.trim();
  if (!text) return;

  const btn    = document.getElementById("scan-email-btn");
  const result = document.getElementById("email-result");

  btn.disabled     = true;
  btn.textContent  = "Analyzing...";
  result.style.display = "none";

  try {
    const response = await fetch(`${API_BASE}/scan-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });

    if (!response.ok) throw new Error("API error");
    const data = await response.json();

    const isPhishing = data.classification === "phishing";
    result.className = `email-result ${isPhishing ? "phishing" : "legit"}`;
    result.style.display = "block";

    document.getElementById("email-result-title").textContent = isPhishing
      ? `⚠️ Phishing Email Detected`
      : `✅ Looks Legitimate`;
    document.getElementById("email-result-title").style.color = isPhishing ? "#e74c3c" : "#27ae60";

    document.getElementById("email-result-conf").textContent =
      `Confidence: ${data.confidence}%  ·  Phishing probability: ${(data.phishing_probability * 100).toFixed(1)}%`;

    const ul = document.getElementById("email-reason-list");
    ul.innerHTML = "";
    if (data.reasons && data.reasons.length) {
      data.reasons.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = `⚠ ${r}`;
        ul.appendChild(li);
      });
    }
  } catch (err) {
    result.className     = "email-result phishing";
    result.style.display = "block";
    document.getElementById("email-result-title").textContent = "⚠️ Could not connect to API";
    document.getElementById("email-result-conf").textContent  = "Make sure the backend is running.";
    document.getElementById("email-reason-list").innerHTML    = "";
  } finally {
    btn.disabled    = false;
    btn.textContent = "Analyze Email";
  }
});

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

// ── Init ──────────────────────────────────────────────────────────────────────
checkAPIStatus();
loadCurrentTabResult();
