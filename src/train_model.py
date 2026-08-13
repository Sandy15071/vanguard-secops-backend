import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)


INPUT_FILE = "data/processed_features.csv"
MODEL_FILE = "model/phishing_model.pkl"


def main():

    print("Loading processed dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Dataset shape: {df.shape}")

    # -----------------------------
    # Separate features and labels
    # -----------------------------

    X = df.drop(columns=["label"])
    y = df["label"]

    print(f"Number of features: {X.shape[1]}")

    # -----------------------------
    # Train/test split
    # -----------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"\nTraining samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    # -----------------------------
    # Create Random Forest
    # -----------------------------

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining Random Forest...")

    model.fit(X_train, y_train)

    print("Training complete!")

    # -----------------------------
    # Predictions
    # -----------------------------

    y_pred = model.predict(X_test)

    # -----------------------------
    # Evaluation
    # -----------------------------

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n" + "=" * 50)
    print("MODEL PERFORMANCE")
    print("=" * 50)

    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Legitimate", "Phishing"]
        )
    )

    # -----------------------------
    # Confusion Matrix
    # -----------------------------

    cm = confusion_matrix(y_test, y_pred)

    print("\nConfusion Matrix:")
    print(cm)

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["Legitimate", "Phishing"]
    )

    display.plot()

    plt.title("Phishing Website Detector - Confusion Matrix")
    plt.tight_layout()

    plt.savefig(
        "model/confusion_matrix.png",
        dpi=300
    )

    plt.show()

    # -----------------------------
    # Feature Importance
    # -----------------------------

    importance = pd.DataFrame({
        "feature": X.columns,
        "importance": model.feature_importances_
    })

    importance = importance.sort_values(
        by="importance",
        ascending=False
    )

    print("\nFeature Importance:")
    print(importance.to_string(index=False))

    # -----------------------------
    # Save model
    # -----------------------------

    joblib.dump(model, MODEL_FILE)

    print("\nModel saved successfully!")

    print(f"Model location: {MODEL_FILE}")


if __name__ == "__main__":
    main()