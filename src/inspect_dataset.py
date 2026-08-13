import pandas as pd

DATASET_PATH = "data/phishing_urls.csv"

df = pd.read_csv(
    DATASET_PATH,
    encoding="latin-1",
    engine="python",
    on_bad_lines="warn"
)

print("Dataset shape:")
print(df.shape)

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nDataset information:")
print(df.info())

print("\nLabel distribution:")
print(df["label"].value_counts())