import joblib
import ipaddress
from urllib.parse import urlparse

MODEL_PATH = "ml_model/phishing_model.pkl"

model = joblib.load(MODEL_PATH)

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "count_dots": url.count("."),
        "count_hyphen": url.count("-"),
        "count_at": url.count("@"),
        "count_question": url.count("?"),
        "count_equal": url.count("="),
        "count_slash": url.count("/"),
        "has_https": 1 if url.startswith("https") else 0,
        "has_ip": 0,
        "suspicious_words": 0
    }

    try:
        ipaddress.ip_address(domain)
        features["has_ip"] = 1
    except:
        features["has_ip"] = 0

    words = ["login", "verify", "secure", "update", "bank", "account", "confirm"]
    features["suspicious_words"] = sum(1 for word in words if word in url.lower())

    return list(features.values())

def predict_url(url):
    features = [extract_features(url)]

    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]

    phishing_confidence = round(probability[1] * 100, 2)

    if prediction == 1:
        return "Phishing", phishing_confidence
    else:
        return "Legitimate", phishing_confidence