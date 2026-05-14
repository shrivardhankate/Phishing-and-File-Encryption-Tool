import joblib
import ipaddress
import math
import re
from urllib.parse import urlparse
from collections import Counter

MODEL_PATH = "ml_model/phishing_model.pkl"

model = joblib.load(MODEL_PATH)

# ─── Known brands for spoofing detection ───
KNOWN_BRANDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook",
    "netflix", "instagram", "linkedin", "chase", "wellsfargo",
    "bankofamerica", "twitter", "yahoo", "ebay", "dropbox", "spotify",
]

# URL shortener domains
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
]

# Risky TLDs commonly abused in phishing
RISKY_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".club", ".work",
    ".buzz", ".icu", ".cam", ".rest", ".surf", ".gq",
]

# Suspicious keywords that appear in phishing URLs
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "bank", "account", "confirm",
    "password", "signin", "billing", "suspend", "alert", "unusual",
    "restore", "unlock", "authenticate", "credential", "expire",
]


def _calc_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(url):
    """
    Extract 25 features from a URL for phishing detection.

    Returns a list of numeric feature values in a fixed order.
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    url_lower = url.lower()
    domain_lower = domain.lower()

    # Remove port from domain for analysis
    domain_no_port = domain.split(":")[0]

    # ─── Original 11 features ───
    url_length = len(url)
    domain_length = len(domain)
    count_dots = url.count(".")
    count_hyphen = url.count("-")
    count_at = url.count("@")
    count_question = url.count("?")
    count_equal = url.count("=")
    count_slash = url.count("/")
    has_https = 1 if url.startswith("https") else 0

    has_ip = 0
    try:
        ipaddress.ip_address(domain_no_port)
        has_ip = 1
    except ValueError:
        pass

    suspicious_word_count = sum(1 for w in SUSPICIOUS_WORDS if w in url_lower)

    # ─── 14 New features ───

    # 12. Subdomain count
    parts = domain_no_port.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # 13. Path depth (number of non-empty path segments)
    path_depth = len([seg for seg in path.split("/") if seg])

    # 14. URL entropy
    url_entropy = round(_calc_entropy(url), 4)

    # 15. Digit ratio in URL
    digits = sum(1 for c in url if c.isdigit())
    digit_ratio = round(digits / max(len(url), 1), 4)

    # 16. Special character ratio
    special = sum(1 for c in url if not c.isalnum() and c not in ":/.-_")
    special_char_ratio = round(special / max(len(url), 1), 4)

    # 17. Has URL shortener
    has_shortener = 1 if any(s in domain_lower for s in SHORTENERS) else 0

    # 18. TLD risk score (1 if risky TLD, else 0)
    tld_risk = 1 if any(domain_lower.endswith(tld) for tld in RISKY_TLDS) else 0

    # 19. Has explicit port
    has_port = 1 if ":" in domain and not domain.endswith(":443") and not domain.endswith(":80") else 0

    # 20. Path length
    path_length = len(path)

    # 21. Count of '&' (tracking / redirect chain indicator)
    count_ampersand = url.count("&")

    # 22. Count of '#' (fragment abuse)
    count_hash = url.count("#")

    # 23. Has redirect pattern
    has_redirect = 1 if any(p in url_lower for p in ["redirect", "redir", "url=", "next=", "return=", "goto="]) else 0

    # 24. Brand spoof score — brand name in domain but not the real domain
    brand_spoof_score = 0
    for brand in KNOWN_BRANDS:
        if brand in domain_lower:
            real_domain = f"{brand}.com"
            if domain_lower != real_domain and not domain_lower.endswith(f".{real_domain}"):
                brand_spoof_score += 1

    # 25. Domain contains digits (legit domains rarely have digits)
    domain_has_digits = 1 if any(c.isdigit() for c in domain_no_port.split(".")[0]) else 0

    return [
        url_length, domain_length, count_dots, count_hyphen, count_at,
        count_question, count_equal, count_slash, has_https, has_ip,
        suspicious_word_count, subdomain_count, path_depth, url_entropy,
        digit_ratio, special_char_ratio, has_shortener, tld_risk,
        has_port, path_length, count_ampersand, count_hash,
        has_redirect, brand_spoof_score, domain_has_digits,
    ]


FEATURE_NAMES = [
    "url_length", "domain_length", "count_dots", "count_hyphen", "count_at",
    "count_question", "count_equal", "count_slash", "has_https", "has_ip",
    "suspicious_words", "subdomain_count", "path_depth", "url_entropy",
    "digit_ratio", "special_char_ratio", "has_shortener", "tld_risk",
    "has_port", "path_length", "count_ampersand", "count_hash",
    "has_redirect", "brand_spoof_score", "domain_has_digits",
]


def predict_url(url):
    """
    Predict whether a URL is phishing or legitimate.

    Returns:
        tuple: (label, confidence_percent)
            - label: "Phishing" or "Legitimate"
            - confidence_percent: float 0–100 representing model confidence
    """
    features = [extract_features(url)]

    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]

    if prediction == 1:
        confidence = round(probability[1] * 100, 2)
        return "Phishing", confidence
    else:
        confidence = round(probability[0] * 100, 2)
        return "Legitimate", confidence