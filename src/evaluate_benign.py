import joblib
import pandas as pd

from feature_extractor import extract_features


MODEL_PATH = "model/phishing_model.pkl"
URL_FILE = "data/benign_test_urls.txt"


model = joblib.load(MODEL_PATH)


with open(URL_FILE, "r", encoding="utf-8") as f:
    urls = [line.strip() for line in f if line.strip()]


correct = 0

print("\n" + "=" * 70)
print("EXTERNAL BENIGN URL TEST")
print("=" * 70)

for url in urls:

    features = extract_features(url)
    X = pd.DataFrame([features])

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]

    if prediction == 0:
        result = "LEGITIMATE"
        correct += 1
    else:
        result = "PHISHING"

    print(
        f"{result:<12} "
        f"{probability * 100:6.1f}% phishing    "
        f"{url}"
    )


accuracy = correct / len(urls) * 100

print("\n" + "=" * 70)
print(f"Correct:  {correct}/{len(urls)}")
print(f"Accuracy: {accuracy:.1f}%")
print("=" * 70)