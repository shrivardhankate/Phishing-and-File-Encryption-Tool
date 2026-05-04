import pandas as pd
import re
import joblib
import ipaddress
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

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

df = pd.read_csv("ml_model/phishing_urls.csv")

X = df["url"].apply(extract_features).tolist()
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("Model Accuracy:", accuracy)

joblib.dump(model, "ml_model/phishing_model.pkl")
print("Model saved successfully!")