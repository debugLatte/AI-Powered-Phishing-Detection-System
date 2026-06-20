"""
train.py — Train URL phishing classifier and Email classifier.
Run: python train.py
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features.url_features import extract_features, get_feature_names
from features.email_features import extract_email_features, get_email_feature_names

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
DATA_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
os.makedirs(MODELS_DIR, exist_ok=True)



#  URL MODEL

def build_url_features(df: pd.DataFrame) -> pd.DataFrame:
    print(f"  Extracting features from {len(df):,} URLs...")
    feature_names = get_feature_names()
    rows = []
    for i, url in enumerate(df["url"]):
        if i % 50000 == 0:
            print(f"    {i:,}/{len(df):,}")
        try:
            f = extract_features(str(url))
            rows.append([f.get(k, 0) for k in sorted(feature_names)])
        except Exception:
            rows.append([0] * len(feature_names))
    return pd.DataFrame(rows, columns=sorted(feature_names))


def train_url_model():
    print("\n" + "="*60)
    print("TRAINING URL PHISHING CLASSIFIER")
    print("="*60)

    csv_path = os.path.join(DATA_DIR, "urls_raw.csv")
    if not os.path.exists(csv_path):
        print(f"ERROR: Dataset not found at {csv_path}")
        print("Run: python download_data.py first")
        return

    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df):,} URLs — labels: {df['label'].value_counts().to_dict()}")

    # Balance classes: sample equal good/bad
    bad = df[df["label"] == "bad"]
    good = df[df["label"] == "good"].sample(len(bad) * 2, random_state=42)
    df = pd.concat([bad, good]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Balanced to {len(df):,} URLs")

    y = (df["label"] == "bad").astype(int).values
    X = build_url_features(df)

    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── Train Random Forest 
    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_prob)
    print(f"  Accuracy : {acc:.4f}")
    print(f"  ROC-AUC  : {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

    # ── Feature importances 
    importances = dict(zip(feature_names, rf.feature_importances_))
    top = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:10]
    print("\nTop 10 most important features:")
    for name, imp in top:
        print(f"  {name:<35} {imp:.4f}")

    # ── Save model 
    model_path = os.path.join(MODELS_DIR, "url_classifier.pkl")
    meta_path  = os.path.join(MODELS_DIR, "url_model_meta.json")

    joblib.dump(rf, model_path)
    with open(meta_path, "w") as fp:
        json.dump({
            "feature_names": feature_names,
            "accuracy": round(acc, 4),
            "roc_auc": round(auc, 4),
            "top_features": [n for n, _ in top],
        }, fp, indent=2)

    print(f"\n✅ URL model saved → {model_path}")
    return rf, feature_names



#  EMAIL MODEL  (synthetic + rule-based training data)


PHISHING_EMAILS = [
    "Your account will be SUSPENDED immediately. Click here NOW to verify your password or lose access forever!",
    "URGENT: Unusual activity detected on your account. Verify your credentials immediately or your account will be terminated.",
    "Dear Customer, your payment method has expired. Update your billing information now to avoid service interruption.",
    "You have won a $1,000,000 prize! Click the link immediately to claim your reward before it expires today!",
    "Security Alert: Your account has been compromised. Click here to reset your password right now.",
    "Final Notice: Your account will be permanently deleted in 24 hours unless you verify your information.",
    "CONGRATULATIONS! You have been selected as our lucky winner. Provide your bank details to receive your prize.",
    "Your Apple ID has been locked. Verify your account at http://192.168.1.1/apple/login.php immediately.",
    "Dear valued customer, we detected suspicious login to your PayPal account. Confirm your identity now.",
    "Your Netflix subscription will be cancelled. Update your payment information by clicking the link below.",
    "IRS Tax Refund: You are eligible for a $3,200 refund. Provide your SSN and bank account number.",
    "Dear user, your email storage is full. Click here immediately to upgrade or your emails will be deleted.",
    "URGENT ACTION REQUIRED: Your bank account has been restricted. Call us immediately to restore access.",
    "Your package could not be delivered. Pay the $2.99 customs fee within 24 hours to release your parcel.",
    "Security breach detected! Change your password immediately using the link below before your account is locked.",
    "You have a pending wire transfer. Confirm your banking credentials to receive $50,000.",
    "Your Microsoft account will expire in 2 days. Update your subscription now to avoid losing your files.",
    "ALERT: Unauthorized access to your account from Russia. Verify your identity now or account will be banned.",
    "Dear customer, your credit card was declined. Update payment details now to continue your subscription.",
    "Limited time offer! Claim your free iPhone now! Click here before the offer expires in 1 hour!",
]

LEGIT_EMAILS = [
    "Hi team, please find attached the meeting notes from yesterday. Let me know if you have any questions.",
    "Thanks for your purchase! Your order #12345 has been confirmed and will ship within 3-5 business days.",
    "Here is the agenda for our weekly sync on Friday. Please review and add any items you would like to discuss.",
    "I wanted to follow up on our conversation from last week. Have you had a chance to review the proposal?",
    "Your password has been successfully updated. If you did not make this change, please contact support.",
    "Welcome to our newsletter! You signed up to receive updates about our products and services.",
    "Your monthly statement is now available. Log in to your account to view your recent transactions.",
    "Thank you for contacting customer support. We will get back to you within 24 hours.",
    "Reminder: Your dentist appointment is scheduled for Tuesday at 2:00 PM. Reply to confirm.",
    "The project deadline has been extended to next Friday. Please update your timelines accordingly.",
    "Happy birthday! We hope you have a wonderful day filled with joy and celebration.",
    "Your GitHub pull request has been approved and merged into the main branch.",
    "Invitation: You have been invited to join the team workspace. Click accept to get started.",
    "Your subscription renewal is coming up on December 1st. You can manage your plan in settings.",
    "Meeting notes from today's standup are shared in the team channel. Great work everyone!",
    "Your flight booking is confirmed. Check in opens 24 hours before departure.",
    "We noticed you left items in your cart. Here is a summary of what you saved for later.",
    "Your report has been successfully submitted. You will receive a confirmation email shortly.",
    "The system maintenance is scheduled for Sunday 2-4 AM. Services will be temporarily unavailable.",
    "Please review the attached document and provide your feedback by end of week.",
]


def train_email_model():
    print("\n" + "="*60)
    print("TRAINING EMAIL PHISHING CLASSIFIER")
    print("="*60)

    # Build features
    feature_names = get_email_feature_names()
    rows, labels = [], []

    for email in PHISHING_EMAILS:
        f = extract_email_features(email)
        rows.append([f.get(k, 0) for k in sorted(feature_names)])
        labels.append(1)

    for email in LEGIT_EMAILS:
        f = extract_email_features(email)
        rows.append([f.get(k, 0) for k in sorted(feature_names)])
        labels.append(0)

    X = pd.DataFrame(rows, columns=sorted(feature_names))
    y = np.array(labels)

    print(f"  Training samples: {len(y)} (phishing: {y.sum()}, legit: {(y==0).sum()})")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)),
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    print(f"  Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

    model_path = os.path.join(MODELS_DIR, "email_classifier.pkl")
    meta_path  = os.path.join(MODELS_DIR, "email_model_meta.json")

    joblib.dump(pipeline, model_path)
    with open(meta_path, "w") as fp:
        json.dump({
            "feature_names": sorted(feature_names),
            "accuracy": round(acc, 4),
        }, fp, indent=2)

    print(f"\n✅ Email model saved → {model_path}")
    return pipeline



#  MAIN

if __name__ == "__main__":
    print("🚀 Phishing Detector — Model Training")
    print("This will take a few minutes for the URL model...\n")

    url_model = train_url_model()
    email_model = train_email_model()

    print("\n" + "="*60)
    print("✅ ALL MODELS TRAINED AND SAVED")
    print("="*60)
    print(f"Models directory: {MODELS_DIR}")
    print("Files saved:")
    for f in os.listdir(MODELS_DIR):
        size = os.path.getsize(os.path.join(MODELS_DIR, f))
        print(f"  {f} ({size/1024:.1f} KB)")
