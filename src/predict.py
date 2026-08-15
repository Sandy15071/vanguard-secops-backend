import re
import joblib
import pandas as pd
from feature_extractor import extract_features

MODEL_FILE = "model/phishing_model.pkl"
VECTORIZER_FILE = "model/tfidf_vectorizer.pkl"


def predict_url(url):
    features = extract_features(url)
    handcrafted_df = pd.DataFrame([features])

    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)
    cleaned_url = re.sub(r"^https?://(www\.)?", "", url.lower())

    tfidf_matrix = vectorizer.transform([cleaned_url])
    tfidf_cols = [f"tfidf_{name}" for name in vectorizer.get_feature_names_out()]
    tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=tfidf_cols)

    full_features = pd.concat([handcrafted_df, tfidf_df], axis=1)

    prediction = model.predict(full_features)[0]
    probabilities = model.predict_proba(full_features)[0]

    return prediction, probabilities[0], probabilities[1]


def main():
    print("=" * 60)
    print("       PHISHING WEBSITE DETECTOR")
    print("=" * 60)

    while True:
        url = input("\nEnter a URL (or type 'exit' to quit): ")

        if url.lower() == "exit":
            print("Goodbye!")
            break

        if not url.strip():
            print("Please enter a URL.")
            continue

        try:
            prediction, leg_prob, phish_prob = predict_url(url)
            print("\n" + "-" * 60)
            if prediction == 1:
                print("RESULT: 🔴 POTENTIAL PHISHING")
                print(f"Phishing probability: {phish_prob * 100:.2f}%")
            else:
                print("RESULT: 🟢 LIKELY LEGITIMATE")
                print(f"Legitimate probability: {leg_prob * 100:.2f}%")
            print("-" * 60)

        except Exception as e:
            print(f"\nError analyzing URL: {e}")


if __name__ == "__main__":
    main()