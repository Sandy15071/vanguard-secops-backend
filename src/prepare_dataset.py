import re
import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from feature_extractor import extract_features

INPUT_FILE = "data/phishing_urls.csv"
BENIGN_TRAINING_FILE = "data/benign_training_urls.txt"
OUTPUT_FILE = "data/processed_features.csv"
VECTORIZER_FILE = "model/tfidf_vectorizer.pkl"


def load_original_dataset():
    print("Loading original dataset...")
    df = pd.read_csv(
        INPUT_FILE,
        encoding="latin-1",
        engine="python",
        on_bad_lines="skip"
    )
    df = df[["domain", "label"]]
    df = df.dropna(subset=["domain", "label"])
    df["label"] = df["label"].astype(int)
    return df


def load_benign_urls():
    print("Loading benign training URLs...")
    with open(BENIGN_TRAINING_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    return pd.DataFrame({"domain": urls, "label": 0})


def extract_dataset_features(df):
    feature_rows = []
    total = len(df)
    print(f"Extracting handcrafted features from {total} URLs...")

    for index, row in df.iterrows():
        url = str(row["domain"])
        label = row["label"]
        try:
            features = extract_features(url)
            features["label"] = label
            feature_rows.append(features)
        except Exception as e:
            print(f"Error processing URL at row {index}: {e}")

        if (index + 1) % 10000 == 0:
            print(f"Processed {index + 1}/{total}")

    return pd.DataFrame(feature_rows)


def main():
    original_df = load_original_dataset()
    print(f"Loaded {len(original_df)} original URLs.")

    benign_df = load_benign_urls()
    print(f"Loaded {len(benign_df)} benign training URLs.")

    combined_df = pd.concat([original_df, benign_df], ignore_index=True)
    print(f"\nCombined dataset size: {len(combined_df)}")

    # 1. Extract Handcrafted Features
    processed_df = extract_dataset_features(combined_df)

    # 2. Extract Character N-Gram TF-IDF Features
    print("\nFitting Character N-Gram TF-IDF Vectorizer (3-5 grams, max_features=100)...")
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=100,
        lowercase=True
    )

    raw_urls = combined_df["domain"].astype(str).tolist()
    cleaned_urls = [re.sub(r"^https?://(www\.)?", "", u.lower()) for u in raw_urls]
    tfidf_matrix = vectorizer.fit_transform(cleaned_urls)
    tfidf_cols = [f"tfidf_{name}" for name in vectorizer.get_feature_names_out()]
    tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=tfidf_cols)

    # Ensure model directory exists
    os.makedirs("model", exist_ok=True)
    joblib.dump(vectorizer, VECTORIZER_FILE)
    print(f"Saved fitted TF-IDF vectorizer to {VECTORIZER_FILE}")

    # 3. Combine Handcrafted + TF-IDF Features
    labels = processed_df["label"]
    processed_df = processed_df.drop(columns=["label"])

    final_df = pd.concat([processed_df, tfidf_df], axis=1)
    final_df["label"] = labels

    final_df.to_csv(OUTPUT_FILE, index=False)

    print("\nFeature extraction & vectorization complete!")
    print(f"Saved processed dataset to: {OUTPUT_FILE}")
    print(f"Processed dataset shape: {final_df.shape}")


if __name__ == "__main__":
    main()