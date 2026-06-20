const API_URL = 'http://localhost:8000';

/* ── Nav switching ─────────────────────────────────────────────── */
document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.dataset.tab;
        document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(tabName).classList.add('active');
    });
});

/* ── Tick meter builder (signature element) ───────────────────── */
function buildMeter(score, severity) {
    const totalTicks = 20;
    const lit = Math.round((score / 100) * totalTicks);
    let html = '<div class="meter">';
    for (let i = 0; i < totalTicks; i++) {
        const isLit = i < lit;
        html += `<div class="meter-tick ${isLit ? `lit ${severity}` : ''}"></div>`;
    }
    html += '</div>';
    return html;
}

/* ── URL Scanner ───────────────────────────────────────────────── */
document.getElementById('urlScanBtn').addEventListener('click', scanURL);
document.getElementById('urlInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') scanURL();
});
document.getElementById('urlSampleBtn').addEventListener('click', () => {
    document.getElementById('urlInput').value = 'https://amaz0n-login-verification.xyz';
    scanURL();
});

async function scanURL() {
    const url = document.getElementById('urlInput').value.trim();
    const resultDiv = document.getElementById('urlResult');

    if (!url) {
        resultDiv.innerHTML = `<div class="error-box">Enter a URL before running a scan.</div>`;
        return;
    }

    resultDiv.innerHTML = `<div class="loading-row"><span class="spinner"></span>scanning target…</div>`;
    document.getElementById('urlScanBtn').disabled = true;

    try {
        const response = await fetch(`${API_URL}/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            resultDiv.innerHTML = `<div class="error-box">Error: ${escapeHtml(data.detail)}</div>`;
            return;
        }

        displayURLResult(data);
    } catch (error) {
        resultDiv.innerHTML = `<div class="error-box">Connection error: ${escapeHtml(error.message)}<br><br>Make sure the backend is running — <code>python api.py</code> in the backend folder.</div>`;
    } finally {
        document.getElementById('urlScanBtn').disabled = false;
    }
}

function displayURLResult(data) {
    const resultDiv = document.getElementById('urlResult');
    const riskScore = data.risk_score;
    const classification = data.classification; // safe | suspicious | phishing

    let html = `
        <div class="card">
            <div class="card-top">
                <span class="stamp ${classification}">${classification}</span>
                <div class="score-block">
                    <div class="score-num ${classification}">${String(riskScore).padStart(3, '0')}</div>
                    <div class="score-suffix">/ 100 risk</div>
                </div>
            </div>
            ${buildMeter(riskScore, classification)}
            <div class="card-body">
                <div class="field-row"><span class="field-key">TARGET</span><span class="field-val">${escapeHtml(data.url)}</span></div>
                <div class="field-row"><span class="field-key">PROBABILITY</span><span class="field-val">${(data.phishing_probability * 100).toFixed(1)}%</span></div>
    `;

    if (data.brand_impersonation) {
        const brand = data.brand_impersonation;
        html += `
            <div class="brand-alert">
                <span class="glyph">⚠</span>
                <div>
                    <strong>Brand impersonation detected</strong> — ${escapeHtml(brand.message)}
                    <small>similarity score: ${brand.similarity_score}%</small>
                </div>
            </div>
        `;
    }

    if (data.reasons && data.reasons.length > 0) {
        html += `
            <div class="signals-title">Detected indicators</div>
            <ul class="signal-list">
                ${data.reasons.map(r => `<li class="signal-item"><span class="arrow">→</span><span>${escapeHtml(r)}</span></li>`).join('')}
            </ul>
        `;
    }

    html += `</div></div>`;
    resultDiv.innerHTML = html;
}

/* ── Email Scanner ─────────────────────────────────────────────── */
document.getElementById('emailScanBtn').addEventListener('click', scanEmail);
document.getElementById('emailInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) scanEmail();
});
document.getElementById('emailSampleBtn').addEventListener('click', () => {
    document.getElementById('emailInput').value = "Your account will be SUSPENDED immediately. Click here NOW to verify your password or lose access forever!";
    scanEmail();
});

async function scanEmail() {
    const text = document.getElementById('emailInput').value.trim();
    const resultDiv = document.getElementById('emailResult');

    if (!text) {
        resultDiv.innerHTML = `<div class="error-box">Paste email text before running a scan.</div>`;
        return;
    }

    resultDiv.innerHTML = `<div class="loading-row"><span class="spinner"></span>analyzing message…</div>`;
    document.getElementById('emailScanBtn').disabled = true;

    try {
        const response = await fetch(`${API_URL}/scan-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });

        const data = await response.json();

        if (!response.ok) {
            resultDiv.innerHTML = `<div class="error-box">Error: ${escapeHtml(data.detail)}</div>`;
            return;
        }

        displayEmailResult(data);
    } catch (error) {
        resultDiv.innerHTML = `<div class="error-box">Connection error: ${escapeHtml(error.message)}<br><br>Make sure the backend is running — <code>python api.py</code> in the backend folder.</div>`;
    } finally {
        document.getElementById('emailScanBtn').disabled = false;
    }
}

function displayEmailResult(data) {
    const resultDiv = document.getElementById('emailResult');
    const classification = data.classification; // legitimate | phishing
    // NOTE: backend already returns confidence on a 0-100 scale — do not
    // multiply by 100 again here (that was the earlier display bug).
    const confidence = data.confidence.toFixed(1);
    const meterSeverity = classification === 'phishing' ? 'phishing' : 'safe';
    const meterScore = classification === 'phishing' ? data.confidence : (100 - data.confidence);

    let html = `
        <div class="card">
            <div class="card-top">
                <span class="stamp ${classification}">${classification}</span>
                <div class="score-block">
                    <div class="score-num ${meterSeverity}">${confidence}%</div>
                    <div class="score-suffix">confidence</div>
                </div>
            </div>
            ${buildMeter(meterScore, meterSeverity)}
            <div class="card-body">
                <div class="field-row"><span class="field-key">SIGNALS</span><span class="field-val">${data.signal_count} / 6 triggered</span></div>
    `;

    if (data.reasons && data.reasons.length > 0) {
        html += `
            <div class="signals-title">Analysis details</div>
            <ul class="signal-list">
                ${data.reasons.map(r => `<li class="signal-item"><span class="arrow">→</span><span>${escapeHtml(r)}</span></li>`).join('')}
            </ul>
        `;
    } else {
        html += `
            <div class="signals-title">Analysis details</div>
            <ul class="signal-list">
                <li class="signal-item"><span class="arrow">→</span><span>No phishing indicators detected in this message.</span></li>
            </ul>
        `;
    }

    html += `</div></div>`;
    resultDiv.innerHTML = html;
}

/* ── Health Check ──────────────────────────────────────────────── */
document.getElementById('healthBtn').addEventListener('click', checkHealth);

async function checkHealth() {
    const resultDiv = document.getElementById('healthResult');
    resultDiv.innerHTML = `<div class="loading-row"><span class="spinner"></span>checking system…</div>`;
    document.getElementById('healthBtn').disabled = true;

    try {
        const response = await fetch(`${API_URL}/health`);
        const data = await response.json();

        let html = `<div class="card"><div class="card-body" style="padding-top:20px;">`;
        html += healthRow('API status', data.status === 'ok' ? 'online' : 'down', data.status === 'ok');
        html += healthRow('URL model loaded', data.url_model ? 'yes' : 'no', data.url_model);
        html += healthRow('Email model loaded', data.email_model ? 'yes' : 'no', data.email_model);
        if (data.url_model_accuracy != null) {
            html += healthRow('URL model accuracy', `${(data.url_model_accuracy * 100).toFixed(2)}%`, true);
        }
        if (data.email_model_accuracy != null) {
            html += healthRow('Email model accuracy', `${(data.email_model_accuracy * 100).toFixed(2)}%`, true);
        }
        html += `</div></div>`;
        resultDiv.innerHTML = html;
        setStatusPill(true);
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <strong>Connection error:</strong> ${escapeHtml(error.message)}<br><br>
                Make sure the API is running — <code>python api.py</code> in the backend folder.
            </div>
        `;
        setStatusPill(false);
    } finally {
        document.getElementById('healthBtn').disabled = false;
    }
}

function healthRow(key, val, ok) {
    return `
        <div class="health-row">
            <span class="health-key">${escapeHtml(key)}</span>
            <span class="health-val ${ok ? 'ok' : 'fail'}">${escapeHtml(String(val))}</span>
        </div>
    `;
}

/* ── Status pill (sidebar) ────────────────────────────────────── */
async function refreshStatusPill() {
    try {
        const response = await fetch(`${API_URL}/health`, { signal: AbortSignal.timeout(2500) });
        setStatusPill(response.ok);
    } catch {
        setStatusPill(false);
    }
}

function setStatusPill(isOnline) {
    const dot = document.getElementById('apiStatusDot');
    const text = document.getElementById('apiStatusText');
    dot.classList.toggle('online', isOnline);
    dot.classList.toggle('offline', !isOnline);
    text.textContent = isOnline ? 'API online' : 'API offline';
}

/* ── Utility ───────────────────────────────────────────────────── */
function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

document.addEventListener('DOMContentLoaded', refreshStatusPill);
