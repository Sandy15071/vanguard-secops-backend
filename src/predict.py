import joblib
import pandas as pd

from feature_extractor import extract_features


MODEL_FILE = "model/phishing_model.pkl"


def predict_url(url):

    # Extract the same features used during training
    features = extract_features(url)

    # Convert dictionary to DataFrame
    feature_data = pd.DataFrame([features])

    # Load trained model
    model = joblib.load(MODEL_FILE)

    # Make prediction
    prediction = model.predict(feature_data)[0]

    # Get probability
    probabilities = model.predict_proba(feature_data)[0]

    legitimate_probability = probabilities[0]
    phishing_probability = probabilities[1]

    return (
        prediction,
        legitimate_probability,
        phishing_probability
    )


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

            prediction, legitimate_probability, phishing_probability = (
                predict_url(url)
            )

            print("\n" + "-" * 60)

            if prediction == 1:

                print("RESULT: 🔴 POTENTIAL PHISHING")

                print(
                    f"Phishing probability: "
                    f"{phishing_probability * 100:.2f}%"
                )

            else:

                print("RESULT: 🟢 LIKELY LEGITIMATE")

                print(
                    f"Legitimate probability: "
                    f"{legitimate_probability * 100:.2f}%"
                )

            print("-" * 60)

        except Exception as e:

            print(f"\nError analyzing URL: {e}")


if __name__ == "__main__":
    main()