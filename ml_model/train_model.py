"""
Train a RandomForestClassifier on phishing_urls.csv and save to phishing_model.pkl.
Uses the same 25-feature extract_features() as ml_phishing.py.
"""

import csv
import joblib
import math
import ipaddress
from collections import Counter
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ─── Constants (must match ml_phishing.py exactly) ───

KNOWN_BRANDS = [
    "google",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "facebook",
    "netflix",
    "instagram",
    "linkedin",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "twitter",
    "yahoo",
    "ebay",
    "dropbox",
    "spotify",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
]

RISKY_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".xyz",
    ".top",
    ".club",
    ".work",
    ".buzz",
    ".icu",
    ".cam",
    ".rest",
    ".surf",
    ".gq",
]

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "account",
    "confirm",
    "password",
    "signin",
    "billing",
    "suspend",
    "alert",
    "unusual",
    "restore",
    "unlock",
    "authenticate",
    "credential",
    "expire",
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
    Must stay in sync with ml_phishing.py.
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    url_lower = url.lower()
    domain_lower = domain.lower()
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
    parts = domain_no_port.split(".")
    subdomain_count = max(0, len(parts) - 2)

    path_depth = len([seg for seg in path.split("/") if seg])

    url_entropy = round(_calc_entropy(url), 4)

    digits = sum(1 for c in url if c.isdigit())
    digit_ratio = round(digits / max(len(url), 1), 4)

    special = sum(1 for c in url if not c.isalnum() and c not in ":/.-_")
    special_char_ratio = round(special / max(len(url), 1), 4)

    has_shortener = 1 if any(s in domain_lower for s in SHORTENERS) else 0

    tld_risk = 1 if any(domain_lower.endswith(tld) for tld in RISKY_TLDS) else 0

    has_port = (
        1
        if ":" in domain and not domain.endswith(":443") and not domain.endswith(":80")
        else 0
    )

    path_length = len(path)

    count_ampersand = url.count("&")
    count_hash = url.count("#")

    has_redirect = (
        1
        if any(
            p in url_lower
            for p in ["redirect", "redir", "url=", "next=", "return=", "goto="]
        )
        else 0
    )

    brand_spoof_score = 0
    for brand in KNOWN_BRANDS:
        if brand in domain_lower:
            real_domain = f"{brand}.com"
            if domain_lower != real_domain and not domain_lower.endswith(
                f".{real_domain}"
            ):
                brand_spoof_score += 1

    domain_has_digits = (
        1 if any(c.isdigit() for c in domain_no_port.split(".")[0]) else 0
    )

    return [
        url_length,
        domain_length,
        count_dots,
        count_hyphen,
        count_at,
        count_question,
        count_equal,
        count_slash,
        has_https,
        has_ip,
        suspicious_word_count,
        subdomain_count,
        path_depth,
        url_entropy,
        digit_ratio,
        special_char_ratio,
        has_shortener,
        tld_risk,
        has_port,
        path_length,
        count_ampersand,
        count_hash,
        has_redirect,
        brand_spoof_score,
        domain_has_digits,
    ]


def main():
    # Load dataset
    dataset_path = "ml_model/phishing_urls.csv"
    X, y = [], []

    with open(dataset_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = extract_features(row["url"])
            X.append(features)
            y.append(int(row["label"]))

    print(f"Loaded {len(X)} samples ({sum(y)} phishing, {len(y) - sum(y)} legitimate)")
    print(f"Feature count: {len(X[0])}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(
        classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    )

    # Save
    model_path = "ml_model/phishing_model.pkl"
    joblib.dump(clf, model_path)
    print(f"\nModel saved to {model_path}")


if __name__ == "__main__":
    main()
