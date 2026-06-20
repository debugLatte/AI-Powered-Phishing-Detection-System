"""
api.py — FastAPI backend for Phishing Detector
Endpoints:
  POST /scan-url    → analyze a URL
  POST /scan-email  → analyze email text
  GET  /health      → status check
"""

import os
import sys
import json
import joblib
import urllib.parse
import numpy as np
import pandas as pd
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.url_features import extract_features, get_feature_names, brand_impersonation
from features.email_features import extract_email_features, get_email_feature_names, explain_email

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Phishing Detector API",
    description="AI-powered phishing detection for URLs and emails",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # In production, restrict this to your extension ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Load models ───────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "..", "models")

def load_model(name: str):
    path = os.path.join(MODELS_DIR, name)
    if not os.path.exists(path):
        return None
    return joblib.load(path)

def load_meta(name: str) -> dict:
    path = os.path.join(MODELS_DIR, name)
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)

url_model    = load_model("url_classifier.pkl")
email_model  = load_model("email_classifier.pkl")
url_meta     = load_meta("url_model_meta.json")
email_meta   = load_meta("email_model_meta.json")

print(f"✅ URL model loaded: {url_model is not None}")
print(f"✅ Email model loaded: {email_model is not None}")


# ── Trusted domain whitelist (major legitimate sites) ─────────────────────────
TRUSTED_DOMAINS = {
    "google.com", "www.google.com", "youtube.com", "facebook.com",
    "twitter.com", "x.com", "instagram.com", "linkedin.com", "reddit.com",
    "github.com", "stackoverflow.com", "wikipedia.org", "amazon.com",
    "apple.com", "microsoft.com", "netflix.com", "spotify.com",
    "dropbox.com", "zoom.us", "slack.com", "discord.com", "twitch.tv",
    "medium.com", "notion.so", "figma.com", "vercel.app", "netlify.app",
    "cloudflare.com", "aws.amazon.com", "console.cloud.google.com",
    "anthropic.com", "openai.com", "huggingface.co",
}

def is_trusted_domain(url: str) -> bool:
    """Check if URL belongs to a known-safe major domain."""
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        host = parsed.netloc.lower().replace("www.", "")
        return host in TRUSTED_DOMAINS or any(
            host.endswith("." + d) for d in TRUSTED_DOMAINS
        )
    except Exception:
        return False


class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    text: str
    sender: Optional[str] = None
    subject: Optional[str] = None

class URLResponse(BaseModel):
    url: str
    risk_score: int          # 0-100
    classification: str      # "safe" | "suspicious" | "phishing"
    phishing_probability: float
    reasons: list[str]
    brand_impersonation: Optional[dict]
    features: dict

class EmailResponse(BaseModel):
    classification: str      # "legitimate" | "phishing"
    confidence: float
    phishing_probability: float
    reasons: list[str]
    signal_count: int


# ── Helper functions ──────────────────────────────────────────────────────────
def classify_risk(prob: float) -> str:
    if prob >= 0.7:
        return "phishing"
    elif prob >= 0.4:
        return "suspicious"
    return "safe"

def prob_to_score(prob: float) -> int:
    return min(100, max(0, int(prob * 100)))

def explain_url(features: dict, prob: float) -> list[str]:
    """Generate human-readable reasons for a URL risk score."""
    reasons = []

    brand = features.get("impersonated_brand")
    brand_score = features.get("brand_impersonation_score", 0)
    if brand and brand_score >= 70:
        reasons.append(f"Mimics {brand.capitalize()} (similarity: {brand_score}%)")

    if features.get("has_ip_address"):
        reasons.append("URL uses raw IP address instead of domain name")

    if features.get("is_suspicious_tld"):
        reasons.append("Uses suspicious top-level domain (e.g., .xyz, .tk, .ml)")

    kw_count = features.get("num_suspicious_keywords", 0)
    if kw_count >= 2:
        reasons.append(f"Contains {kw_count} suspicious keywords (login, verify, secure, etc.)")
    elif kw_count == 1:
        reasons.append("Contains suspicious keyword (login, verify, secure, etc.)")

    if features.get("has_login_keyword") and features.get("has_security_keyword"):
        reasons.append("Combines login + security keywords — common phishing pattern")

    if features.get("num_hyphens", 0) >= 3:
        reasons.append(f"Excessive hyphens in domain ({features['num_hyphens']}) — common obfuscation")

    if features.get("url_length", 0) > 75:
        reasons.append(f"Unusually long URL ({features['url_length']} chars)")

    if features.get("domain_entropy", 0) > 3.8:
        reasons.append(f"High domain entropy ({features['domain_entropy']:.2f}) — looks random/generated")

    if features.get("num_subdomains", 0) >= 3:
        reasons.append(f"Many subdomains ({features['num_subdomains']}) — hiding real domain")

    if features.get("has_at_sign"):
        reasons.append("URL contains @ symbol — can redirect to different host")

    if features.get("num_digits_in_domain", 0) >= 3:
        reasons.append(f"Many digits in domain ({features['num_digits_in_domain']})")

    if features.get("has_double_slash_redirect"):
        reasons.append("Contains double-slash redirect pattern")

    if features.get("has_php_extension"):
        reasons.append("URL ends with .php — common in credential harvesting pages")

    if not reasons and prob > 0.5:
        reasons.append("Multiple subtle indicators of phishing detected by ML model")

    if not reasons:
        reasons.append("No specific phishing indicators detected")

    return reasons


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "url_model": url_model is not None,
        "email_model": email_model is not None,
        "url_model_accuracy": url_meta.get("accuracy"),
        "email_model_accuracy": email_meta.get("accuracy"),
    }


@app.post("/scan-url", response_model=URLResponse)
def scan_url(req: URLRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Short-circuit for trusted major domains
    if is_trusted_domain(url):
        return URLResponse(
            url=url,
            risk_score=2,
            classification="safe",
            phishing_probability=0.02,
            reasons=["Domain is a known trusted major website"],
            brand_impersonation=None,
            features={},
        )

    # Extract features
    try:
        features = extract_features(url)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Feature extraction failed: {str(e)}")

    # Get numeric feature vector in correct order (DataFrame preserves feature names)
    feature_names = sorted(k for k, v in features.items() if isinstance(v, (int, float)))
    X = pd.DataFrame([[features[k] for k in feature_names]], columns=feature_names)

    # Predict
    if url_model is not None:
        prob = float(url_model.predict_proba(X)[0][1])
    else:
        # Fallback heuristic if model not loaded
        prob = min(1.0, (
            features.get("num_suspicious_keywords", 0) * 0.15 +
            features.get("brand_impersonation_score", 0) / 100 * 0.4 +
            features.get("is_suspicious_tld", 0) * 0.25 +
            features.get("has_ip_address", 0) * 0.3
        ))

    risk_score     = prob_to_score(prob)
    classification = classify_risk(prob)
    reasons        = explain_url(features, prob)

    # Brand impersonation block
    brand_name  = features.get("impersonated_brand")
    brand_score = features.get("brand_impersonation_score", 0)
    brand_info  = None
    if brand_name and brand_score >= 70:
        brand_info = {
            "brand": brand_name.capitalize(),
            "similarity_score": brand_score,
            "message": f"Possible impersonation of {brand_name.capitalize()}",
        }

    # Keep only numeric features for response
    numeric_features = {k: v for k, v in features.items() if isinstance(v, (int, float))}

    return URLResponse(
        url=url,
        risk_score=risk_score,
        classification=classification,
        phishing_probability=round(prob, 4),
        reasons=reasons,
        brand_impersonation=brand_info,
        features=numeric_features,
    )


@app.post("/scan-email", response_model=EmailResponse)
def scan_email(req: EmailRequest):
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Email text cannot be empty")

    # Combine subject if provided
    full_text = text
    if req.subject:
        full_text = f"Subject: {req.subject}\n\n{text}"

    features = extract_email_features(full_text)

    feature_names = sorted(k for k, v in features.items() if isinstance(v, (int, float)))
    X = pd.DataFrame([[features[k] for k in feature_names]], columns=feature_names)

    if email_model is not None:
        prob = float(email_model.predict_proba(X)[0][1])
    else:
        # Fallback
        signals = features.get("phishing_signal_count", 0)
        prob = min(0.99, signals / 6.0)

    classification = "phishing" if prob >= 0.5 else "legitimate"
    confidence     = round(max(prob, 1 - prob) * 100, 1)
    reasons        = explain_email(features)

    return EmailResponse(
        classification=classification,
        confidence=confidence,
        phishing_probability=round(prob, 4),
        reasons=reasons,
        signal_count=features.get("phishing_signal_count", 0),
    )


# ── Dev server ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
