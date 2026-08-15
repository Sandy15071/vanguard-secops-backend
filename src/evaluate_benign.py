import re
import joblib
import pandas as pd
from feature_extractor import extract_features

MODEL_PATH = "model/phishing_model.pkl"
VECTORIZER_PATH = "model/tfidf_vectorizer.pkl"
URL_FILE = "data/benign_test_urls.txt"

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

with open(URL_FILE, "r", encoding="utf-8") as f:
    urls = [line.strip() for line in f if line.strip()]

correct = 0

print("\n" + "=" * 70)
print("EXTERNAL BENIGN URL TEST")
print("=" * 70)

for url in urls:
    features = extract_features(url)
    handcrafted_df = pd.DataFrame([features])
    cleaned_url = re.sub(r"^https?://(www\.)?", "", url.lower())

    tfidf_matrix = vectorizer.transform([cleaned_url])
    tfidf_cols = [f"tfidf_{name}" for name in vectorizer.get_feature_names_out()]
    tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=tfidf_cols)

    X = pd.concat([handcrafted_df, tfidf_df], axis=1)

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]

    if prediction == 0:
        result = "LEGITIMATE"
        correct += 1
    else:
        result = "PHISHING"

    print(f"{result:<12} {probability * 100:6.1f}% phishing    {url}")

accuracy = correct / len(urls) * 100

print("\n" + "=" * 70)
print(f"Correct:  {correct}/{len(urls)}")
print(f"Accuracy: {accuracy:.1f}%")
print("=" * 70)