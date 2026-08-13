import pandas as pd
from feature_extractor import extract_features

INPUT_FILE = "data/phishing_urls.csv"
BENIGN_TRAINING_FILE = "data/benign_training_urls.txt"
OUTPUT_FILE = "data/processed_features.csv"


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

    df = pd.DataFrame({
        "domain": urls,
        "label": 0
    })

    return df


def extract_dataset_features(df):

    feature_rows = []

    total = len(df)

    print(f"Extracting features from {total} URLs...")

    for index, row in df.iterrows():

        url = str(row["domain"])
        label = row["label"]

        try:
            features = extract_features(url)
            features["label"] = label

            feature_rows.append(features)

        except Exception as e:
            print(f"Error processing URL at row {index}: {e}")

        if (index + 1) % 5000 == 0:
            print(f"Processed {index + 1}/{total}")

    return pd.DataFrame(feature_rows)


def main():

    # Load original dataset
    original_df = load_original_dataset()

    print(f"Loaded {len(original_df)} original URLs.")

    # Load additional legitimate URLs
    benign_df = load_benign_urls()

    print(f"Loaded {len(benign_df)} benign training URLs.")

    # Combine datasets
    df = pd.concat(
        [original_df, benign_df],
        ignore_index=True
    )

    print(f"\nCombined dataset size: {len(df)}")

    print("\nCombined label distribution:")
    print(df["label"].value_counts())

    # Extract features
    processed_df = extract_dataset_features(df)

    # Save processed dataset
    processed_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\nFeature extraction complete!")

    print("Saved processed dataset to:")
    print(OUTPUT_FILE)

    print("\nProcessed dataset shape:")
    print(processed_df.shape)

    print("\nFeatures:")
    print(processed_df.columns.tolist())


if __name__ == "__main__":
    main()