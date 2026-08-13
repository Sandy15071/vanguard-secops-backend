from src.feature_extractor import extract_features


test_urls = [
    "https://www.google.com",
    "https://www.amazon.in",
    "http://192.168.1.10/login",
    "https://secure-login-account-verification.com/verify",
]


for url in test_urls:

    print("\n" + "=" * 60)
    print("URL:", url)
    print("=" * 60)

    features = extract_features(url)

    for feature, value in features.items():
        print(f"{feature:25} : {value}")