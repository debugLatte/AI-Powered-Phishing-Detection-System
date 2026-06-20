/**
 * content.js — PhishGuard Content Script
 * Detects login forms + shows in-page warning overlay.
 */

let warningShown = false;

// ── Listen for warning from background ───────────────────────────────────────
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SHOW_WARNING" && !warningShown) {
    showWarningOverlay(message.result);
    warningShown = true;
  }
});

// ── Create warning overlay ────────────────────────────────────────────────────
function showWarningOverlay(result) {
  // Don't show twice
  if (document.getElementById("phishguard-overlay")) return;

  const score  = result.risk_score;
  const reasons = result.reasons || [];

  const overlay = document.createElement("div");
  overlay.id    = "phishguard-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.85);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  `;

  const reasonsHTML = reasons
    .map((r) => `<li style="margin:6px 0; color:#ffd6d6;">⚠ ${r}</li>`)
    .join("");

  overlay.innerHTML = `
    <div style="
      background: #1a1a2e;
      border: 2px solid #e74c3c;
      border-radius: 16px;
      padding: 36px 40px;
      max-width: 520px;
      width: 90%;
      text-align: center;
      box-shadow: 0 0 60px rgba(231,76,60,0.4);
    ">
      <div style="font-size: 56px; margin-bottom: 12px;">🛡️</div>

      <h1 style="
        color: #e74c3c;
        font-size: 22px;
        font-weight: 700;
        margin: 0 0 6px;
        letter-spacing: -0.3px;
      ">Dangerous Website Blocked</h1>

      <p style="color:#aaa; font-size:13px; margin:0 0 20px;">
        PhishGuard has detected this site as a potential phishing attack
      </p>

      <!-- Risk score gauge -->
      <div style="
        background: #0d0d1a;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 20px;
      ">
        <div style="color:#fff; font-size:13px; margin-bottom:8px; opacity:0.7;">RISK SCORE</div>
        <div style="font-size:48px; font-weight:800; color:#e74c3c; line-height:1;">${score}</div>
        <div style="color:#aaa; font-size:13px;">/100</div>
        <div style="
          background:#2d2d4e;
          border-radius:4px;
          height:6px;
          margin-top:12px;
          overflow:hidden;
        ">
          <div style="
            background: linear-gradient(90deg, #e67e22, #e74c3c);
            height:100%;
            width:${score}%;
            border-radius:4px;
            transition: width 0.3s;
          "></div>
        </div>
      </div>

      <!-- Reasons -->
      ${reasons.length ? `
      <div style="
        text-align:left;
        background:#0d0d1a;
        border-radius:10px;
        padding:14px 18px;
        margin-bottom:20px;
      ">
        <div style="color:#e74c3c; font-size:12px; font-weight:600; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;">
          Why it's flagged
        </div>
        <ul style="margin:0; padding:0 0 0 4px; list-style:none; font-size:13px;">
          ${reasonsHTML}
        </ul>
      </div>` : ""}

      <!-- URL -->
      <div style="
        background:#0d0d1a;
        border-radius:8px;
        padding:10px 14px;
        margin-bottom:24px;
        word-break:break-all;
        font-size:11px;
        color:#888;
        text-align:left;
      ">
        ${window.location.href}
      </div>

      <!-- Buttons -->
      <div style="display:flex; gap:12px; justify-content:center;">
        <button id="phishguard-back" style="
          background: #27ae60;
          color: white;
          border: none;
          border-radius: 10px;
          padding: 12px 28px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          flex: 1;
        ">← Go Back (Safe)</button>

        <button id="phishguard-proceed" style="
          background: transparent;
          color: #888;
          border: 1px solid #444;
          border-radius: 10px;
          padding: 12px 20px;
          font-size: 13px;
          cursor: pointer;
          flex: 1;
        ">Proceed Anyway</button>
      </div>

      <p style="color:#555; font-size:11px; margin-top:16px;">
        Powered by PhishGuard AI · 93% accuracy
      </p>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("phishguard-back").onclick = () => history.back();
  document.getElementById("phishguard-proceed").onclick = () => {
    overlay.remove();
    warningShown = false;
  };
}

// ── Auto-detect login forms ───────────────────────────────────────────────────
function detectLoginForms() {
  const inputs = document.querySelectorAll('input[type="password"]');
  if (inputs.length > 0) {
    // Page has password field — notify background to note this
    chrome.runtime.sendMessage({
      type: "HAS_LOGIN_FORM",
      url: window.location.href,
    }).catch(() => {});
  }
}

// Run after DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", detectLoginForms);
} else {
  detectLoginForms();
}
