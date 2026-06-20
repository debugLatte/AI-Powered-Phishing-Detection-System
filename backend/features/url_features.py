"""
URL Feature Extractor
Extracts 30+ features from a URL for phishing detection.
"""

import re
import math
import urllib.parse
from collections import Counter

import tldextract

# Use the bundled public-suffix-list snapshot only — don't try to fetch a fresh
# copy from the internet on first run (this caused noisy tracebacks / slow
# startup, and fails outright in offline or restricted-network environments).
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# ── Brand list for impersonation detection ────────────────────────────────────
KNOWN_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "yahoo",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "steam", "ebay", "walmart", "target", "fedex", "ups", "dhl",
    "whatsapp", "telegram", "zoom", "adobe", "spotify", "airbnb",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "account", "update", "verify",
    "secure", "security", "banking", "confirm", "password", "credential",
    "support", "helpdesk", "service", "suspend", "alert", "urgent",
    "payment", "invoice", "billing", "free", "winner", "prize",
    "click", "verify", "validation", "webscr", "ebayisapi",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
    ".click", ".link", ".win", ".download", ".stream", ".science",
    ".party", ".trade", ".date", ".racing", ".accountant",
]

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def levenshtein(s1: str, s2: str) -> int:
    """Fast Levenshtein distance."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def brand_impersonation(domain: str):
    """
    Returns (brand_name, similarity_score 0-100) for the closest brand.
    Returns (None, 0) if no impersonation detected.
    """
    domain_clean = domain.lower().replace("-", "").replace(".", "")
    best_brand, best_score = None, 0

    for brand in KNOWN_BRANDS:
        # Exact match means this domain IS the brand, not impersonating it
        if domain_clean == brand:
            continue

        # Direct substring check
        if brand in domain_clean:
            score = 90
        else:
            dist = levenshtein(domain_clean, brand)
            max_len = max(len(domain_clean), len(brand))
            score = int((1 - dist / max_len) * 100)

        if score > best_score:
            best_score = score
            best_brand = brand

    if best_score >= 70:
        return best_brand, best_score
    return None, 0


def extract_features(url: str) -> dict:
    """
    Extract all features from a URL.
    Returns a dictionary of feature_name -> value.
    """
    # ── Normalize ─────────────────────────────────────────────────────────────
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    ext = _TLD_EXTRACTOR(url)

    full_domain = parsed.netloc.lower()
    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    subdomain = ext.subdomain.lower()
    path = parsed.path
    query = parsed.query
    full_url = url.lower()

    # ── 1. Lexical / Length features ──────────────────────────────────────────
    f = {}
    f["url_length"] = len(url)
    f["domain_length"] = len(full_domain)
    f["path_length"] = len(path)
    f["query_length"] = len(query)

    # ── 2. Character count features ───────────────────────────────────────────
    f["num_dots"] = url.count(".")
    f["num_hyphens"] = url.count("-")
    f["num_underscores"] = url.count("_")
    f["num_slashes"] = url.count("/")
    f["num_at_signs"] = url.count("@")
    f["num_equals"] = url.count("=")
    f["num_ampersand"] = url.count("&")
    f["num_exclamation"] = url.count("!")
    f["num_percent"] = url.count("%")
    f["num_digits_in_domain"] = sum(c.isdigit() for c in full_domain)
    f["digit_ratio_url"] = sum(c.isdigit() for c in url) / max(len(url), 1)
    f["letter_ratio_url"] = sum(c.isalpha() for c in url) / max(len(url), 1)

    # ── 3. Entropy ────────────────────────────────────────────────────────────
    f["url_entropy"] = round(shannon_entropy(url), 4)
    f["domain_entropy"] = round(shannon_entropy(full_domain), 4)
    f["path_entropy"] = round(shannon_entropy(path), 4)

    # ── 4. Special patterns ───────────────────────────────────────────────────
    f["has_ip_address"] = int(bool(
        re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", full_domain)
    ))
    f["has_at_sign"] = int("@" in url)
    f["has_double_slash_redirect"] = int("//" in path)
    f["has_hex_encoding"] = int("%" in url)
    f["is_https"] = int(parsed.scheme == "https")
    f["has_port"] = int(bool(parsed.port))
    f["num_subdomains"] = len(subdomain.split(".")) if subdomain else 0
    f["subdomain_length"] = len(subdomain)

    # ── 5. TLD features ───────────────────────────────────────────────────────
    f["tld_length"] = len(suffix)
    f["is_suspicious_tld"] = int(any(
        full_url.endswith(tld) or f".{suffix}" == tld
        for tld in SUSPICIOUS_TLDS
    ))

    # ── 6. Keyword features ───────────────────────────────────────────────────
    f["num_suspicious_keywords"] = sum(
        kw in full_url for kw in SUSPICIOUS_KEYWORDS
    )
    f["has_login_keyword"] = int(
        any(kw in full_url for kw in ["login", "signin", "sign-in", "logon"])
    )
    f["has_security_keyword"] = int(
        any(kw in full_url for kw in ["secure", "security", "verify", "update"])
    )

    # ── 7. Brand impersonation ────────────────────────────────────────────────
    brand, sim_score = brand_impersonation(domain)
    f["brand_impersonation_score"] = sim_score
    f["impersonated_brand"] = brand or ""

    # ── 8. Path features ──────────────────────────────────────────────────────
    f["num_path_components"] = len([p for p in path.split("/") if p])
    f["has_php_extension"] = int(path.endswith(".php"))
    f["has_html_extension"] = int(path.endswith((".html", ".htm")))
    f["has_exe_extension"] = int(
        any(path.endswith(ext) for ext in [".exe", ".zip", ".rar", ".dmg"])
    )

    return f


def features_to_vector(features: dict) -> list:
    """
    Convert feature dict to numeric vector for ML model.
    Drops non-numeric fields (like impersonated_brand).
    """
    numeric_keys = [k for k, v in features.items() if isinstance(v, (int, float))]
    return [features[k] for k in sorted(numeric_keys)]


def get_feature_names() -> list:
    """Return sorted list of numeric feature names used in the model."""
    sample = extract_features("http://example.com")
    return sorted(k for k, v in sample.items() if isinstance(v, (int, float)))


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://amaz0n-login-security.xyz/verify?account=true",
        "http://192.168.1.1/admin/login.php",
        "https://paypal-secure-update.com/signin",
        "https://micr0soft-support.net/helpdesk",
    ]
    for u in test_urls:
        f = extract_features(u)
        brand, score = f["impersonated_brand"], f["brand_impersonation_score"]
        print(f"\n{u}")
        print(f"  Entropy: {f['url_entropy']}  |  Suspicious KWs: {f['num_suspicious_keywords']}  |  IP: {f['has_ip_address']}")
        if brand:
            print(f"  ⚠️  Impersonates: {brand} ({score}%)")
