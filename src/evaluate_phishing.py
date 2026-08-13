import joblib
import pandas as pd

from feature_extractor import extract_features


MODEL_PATH = "model/phishing_model.pkl"
URL_FILE = "data/external_phishing_test.txt"


model = joblib.load(MODEL_PATH)

with open(URL_FILE, "r", encoding="utf-8") as f:
    urls = [line.strip() for line in f if line.strip()]


correct = 0
missed = 0

print("\n" + "=" * 70)
print("EXTERNAL PHISHING URL TEST")
print("=" * 70)

for url in urls:

    features = extract_features(url)
    X = pd.DataFrame([features])

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]

    if prediction == 1:
        result = "PHISHING"
        correct += 1
    else:
        result = "MISSED"
        missed += 1

    print(
        f"{result:<12} "
        f"{probability * 100:6.1f}% phishing    "
        f"{url}"
    )


detection_rate = correct / len(urls) * 100

print("\n" + "=" * 70)
print(f"Correctly detected: {correct}/{len(urls)}")
print(f"Missed:             {missed}/{len(urls)}")
print(f"Detection rate:     {detection_rate:.1f}%")
print("=" * 70)