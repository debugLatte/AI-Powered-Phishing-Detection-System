"""
Email Feature Extractor
NLP-based feature extraction for phishing email detection.
"""

import re
from collections import Counter

# ── Phishing signal word lists ────────────────────────────────────────────────
URGENCY_WORDS = [
    "immediately", "urgent", "urgently", "right now", "as soon as possible",
    "asap", "today only", "expires", "expiring", "deadline", "limited time",
    "act now", "don't wait", "don't delay", "last chance", "final notice",
    "within 24 hours", "within 48 hours", "must respond", "respond now",
]

THREAT_WORDS = [
    "suspended", "suspend", "terminated", "terminate", "disabled", "disable",
    "blocked", "block", "locked", "lock", "closed", "close", "deactivated",
    "deactivate", "deleted", "delete", "banned", "ban", "restricted",
    "violation", "violated", "illegal", "unauthorized", "fraudulent",
    "unusual activity", "suspicious activity", "breach", "compromised",
]

REWARD_WORDS = [
    "winner", "won", "winning", "prize", "reward", "free", "gift", "bonus",
    "congratulations", "selected", "chosen", "lucky", "cash", "money",
    "million", "lottery", "jackpot", "offer", "deal", "discount",
]

ACTION_WORDS = [
    "click here", "click the link", "click below", "click this",
    "verify now", "verify your", "confirm your", "update your",
    "login now", "log in now", "sign in now", "access here",
    "open attachment", "download now", "call immediately",
    "follow the link", "use this link", "tap here",
]

FINANCIAL_WORDS = [
    "bank account", "credit card", "debit card", "social security",
    "ssn", "account number", "routing number", "payment", "invoice",
    "transfer", "wire", "refund", "billing", "subscription", "charge",
    "overdue", "outstanding balance", "tax", "irs", "customs",
]

SENSITIVE_DATA_WORDS = [
    "password", "username", "login", "credentials", "pin", "passcode",
    "mother's maiden", "date of birth", "dob", "passport", "driver's license",
    "social security", "tax id", "cvv", "security code",
]


def extract_email_features(text: str) -> dict:
    """
    Extract NLP features from email text.
    Returns a feature dictionary.
    """
    text_lower = text.lower()
    words = re.findall(r'\b\w+\b', text_lower)
    sentences = re.split(r'[.!?]+', text)
    word_count = len(words)

    f = {}

    # ── Basic stats ───────────────────────────────────────────────────────────
    f["char_count"] = len(text)
    f["word_count"] = word_count
    f["sentence_count"] = len([s for s in sentences if s.strip()])
    f["avg_word_length"] = (
        sum(len(w) for w in words) / max(word_count, 1)
    )
    f["exclamation_count"] = text.count("!")
    f["question_count"] = text.count("?")
    f["caps_ratio"] = sum(1 for c in text if c.isupper()) / max(len(text), 1)

    # ── URL / Link features ───────────────────────────────────────────────────
    urls = re.findall(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        text
    )
    f["url_count"] = len(urls)
    f["has_url"] = int(len(urls) > 0)
    f["has_ip_url"] = int(any(
        re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u) for u in urls
    ))

    # ── Phishing keyword counts ───────────────────────────────────────────────
    f["urgency_word_count"] = sum(
        1 for w in URGENCY_WORDS if w in text_lower
    )
    f["threat_word_count"] = sum(
        1 for w in THREAT_WORDS if w in text_lower
    )
    f["reward_word_count"] = sum(
        1 for w in REWARD_WORDS if w in text_lower
    )
    f["action_word_count"] = sum(
        1 for w in ACTION_WORDS if w in text_lower
    )
    f["financial_word_count"] = sum(
        1 for w in FINANCIAL_WORDS if w in text_lower
    )
    f["sensitive_data_word_count"] = sum(
        1 for w in SENSITIVE_DATA_WORDS if w in text_lower
    )

    # ── Binary flags ──────────────────────────────────────────────────────────
    f["has_urgency"] = int(f["urgency_word_count"] > 0)
    f["has_threat"] = int(f["threat_word_count"] > 0)
    f["has_reward"] = int(f["reward_word_count"] > 0)
    f["has_action_word"] = int(f["action_word_count"] > 0)
    f["has_financial_content"] = int(f["financial_word_count"] > 0)
    f["requests_sensitive_data"] = int(f["sensitive_data_word_count"] > 0)

    # ── Composite phishing score signals ─────────────────────────────────────
    f["phishing_signal_count"] = (
        f["has_urgency"] + f["has_threat"] + f["has_action_word"] +
        f["requests_sensitive_data"] + f["has_ip_url"] +
        f["has_financial_content"]
    )

    # ── Text pattern features ─────────────────────────────────────────────────
    f["has_greeting"] = int(
        any(g in text_lower for g in ["dear customer", "dear user", "dear account", "dear member", "hello"])
    )
    f["has_signature"] = int(
        any(s in text_lower for s in ["sincerely", "regards", "best regards", "thank you", "thanks"])
    )
    f["has_unsubscribe"] = int("unsubscribe" in text_lower)
    f["digit_ratio"] = sum(c.isdigit() for c in text) / max(len(text), 1)

    return f


def get_email_feature_names() -> list:
    sample = extract_email_features("test email")
    return sorted(k for k, v in sample.items() if isinstance(v, (int, float)))


def explain_email(features: dict) -> list[str]:
    """Return human-readable reasons based on features."""
    reasons = []
    if features.get("has_urgency"):
        reasons.append("Contains urgency language (e.g., 'immediately', 'urgent')")
    if features.get("has_threat"):
        reasons.append("Contains threats (e.g., 'account suspended', 'terminated')")
    if features.get("has_action_word"):
        reasons.append("Pushes user to click a link or take action")
    if features.get("requests_sensitive_data"):
        reasons.append("Requests sensitive data (password, SSN, etc.)")
    if features.get("has_financial_content"):
        reasons.append("Contains financial/payment-related content")
    if features.get("has_ip_url"):
        reasons.append("Contains URL with raw IP address")
    if features.get("url_count", 0) > 3:
        reasons.append(f"High number of URLs ({features['url_count']})")
    if features.get("caps_ratio", 0) > 0.15:
        reasons.append("Excessive use of capital letters")
    if features.get("exclamation_count", 0) > 2:
        reasons.append(f"Many exclamation marks ({features['exclamation_count']})")
    return reasons


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_emails = [
        "Your account will be SUSPENDED immediately. Click here NOW to verify your password or lose access forever!",
        "Hi team, please find attached the meeting notes from yesterday. Let me know if you have any questions.",
        "CONGRATULATIONS! You have WON $1,000,000! Click the link to claim your prize immediately before it expires!",
    ]
    for email in test_emails:
        f = extract_email_features(email)
        reasons = explain_email(f)
        print(f"\nEmail: {email[:60]}...")
        print(f"  Phishing signals: {f['phishing_signal_count']}/6")
        for r in reasons:
            print(f"  ⚠️  {r}")
