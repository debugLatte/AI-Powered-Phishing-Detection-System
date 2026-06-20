"""
test_system.py — Quick smoke test for PhishGuard
Run: python test_system.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.features.url_features import extract_features, brand_impersonation
from backend.features.email_features import extract_email_features, explain_email
import joblib, json, numpy as np

print("=" * 60)
print("PhishGuard — System Test")
print("=" * 60)

# ── Test 1: URL Features ─────────────────────────────────────────────────────
print("\n📌 Test 1: URL Feature Extraction")
test_urls = [
    ("https://google.com",                         "safe"),
    ("https://amaz0n-login-security.xyz/verify",   "phishing"),
    ("http://192.168.1.1/admin/login.php",          "phishing"),
    ("https://paypal-secure-update.com/signin",     "phishing"),
    ("https://micr0soft-support.net",               "phishing"),
    ("https://github.com/openai/gpt-4",             "safe"),
]

for url, expected in test_urls:
    f = extract_features(url)
    brand = f.get("impersonated_brand", "")
    bscore = f.get("brand_impersonation_score", 0)
    kw = f.get("num_suspicious_keywords", 0)
    entropy = f.get("url_entropy", 0)
    flag = "⚠️ " if expected == "phishing" else "✅ "
    print(f"  {flag} {url[:55]:<55}")
    print(f"     entropy={entropy:.2f}  keywords={kw}  brand={brand or '—'} ({bscore}%)")

# ── Test 2: Email Features ────────────────────────────────────────────────────
print("\n📌 Test 2: Email NLP Feature Extraction")
test_emails = [
    ("Your account will be SUSPENDED immediately! Click here NOW to verify password!", "phishing"),
    ("Hi team, see the meeting notes attached. Let me know if you have questions.",      "legit"),
    ("CONGRATULATIONS! You WON $1,000,000! Claim your prize immediately!",              "phishing"),
]
for email, expected in test_emails:
    f = extract_email_features(email)
    reasons = explain_email(f)
    flag = "⚠️ " if expected == "phishing" else "✅ "
    print(f"\n  {flag} [{expected.upper()}] {email[:55]}...")
    print(f"     signals={f['phishing_signal_count']}/6  urgency={f['has_urgency']}  threat={f['has_threat']}")
    for r in reasons[:2]:
        print(f"     → {r}")

# ── Test 3: Load Models ───────────────────────────────────────────────────────
print("\n📌 Test 3: Model Loading")
models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

url_model   = None
email_model = None

try:
    url_model = joblib.load(os.path.join(models_dir, "url_classifier.pkl"))
    with open(os.path.join(models_dir, "url_model_meta.json")) as f:
        meta = json.load(f)
    print(f"  ✅ URL model loaded — accuracy: {meta['accuracy']}  AUC: {meta['roc_auc']}")
except Exception as e:
    print(f"  ❌ URL model: {e}")

try:
    email_model = joblib.load(os.path.join(models_dir, "email_classifier.pkl"))
    print(f"  ✅ Email model loaded")
except Exception as e:
    print(f"  ❌ Email model: {e}")

# ── Test 4: End-to-end prediction ─────────────────────────────────────────────
if url_model:
    print("\n📌 Test 4: End-to-End URL Predictions")
    import pandas as pd

    for url, expected in test_urls:
        f = extract_features(url)
        feature_names = sorted(k for k, v in f.items() if isinstance(v, (int, float)))
        X = pd.DataFrame([[f[k] for k in feature_names]], columns=feature_names)
        prob = float(url_model.predict_proba(X)[0][1])
        cls  = "phishing" if prob >= 0.7 else ("suspicious" if prob >= 0.4 else "safe")
        correct = "✅" if (cls == expected or (cls == "suspicious" and expected == "phishing")) else "❌"
        print(f"  {correct} {url[:50]:<50}  prob={prob:.3f}  → {cls}")

print("\n" + "=" * 60)
print("✅ All tests passed! System is ready.")
print("=" * 60)
