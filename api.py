import joblib
import pandas as pd
import re
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from src.feature_extractor import extract_features
from src.domain_checker import get_extended_domain_info
import math
from collections import Counter
from urllib.parse import urlparse

TARGET_BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "chase", "wellsfargo", "bankofamerica"]

def calculate_entropy(text):
    """Calculates the randomness of a string. High entropy = randomly generated."""
    if not text: return 0
    entropy = 0
    for x in Counter(text).values():
        p_x = float(x) / len(text)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def check_brand_spoofing(url):
    """Checks if a brand name is used in a deceptive way in the domain."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    
    for brand in TARGET_BRANDS:
        if brand in hostname:
            # If it's the actual legitimate domain (e.g., www.paypal.com)
            if hostname == f"{brand}.com" or hostname == f"www.{brand}.com":
                continue
            # If the brand is in the domain but it's NOT the official site -> Spoof!
            return brand.capitalize()
    return None

# Initialize the FastAPI app
app = FastAPI(
    title="Phishing URL Detector API",
    description="An API to analyze URLs and return phishing risk probabilities.",
    version="1.0.0"
)

# Configure CORS to allow requests from your React frontend (Vite runs on port 5173 by default)
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model and vectorizer into memory on startup
MODEL_FILE = "model/compressed_model.pkl"
VECTORIZER_FILE = "model/tfidf_vectorizer.pkl"

try:
    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)
except Exception as e:
    print(f"Error loading model artifacts: {e}")

# Define the expected JSON payload structure
class URLRequest(BaseModel):
    url: str

@app.post("/analyze")
def analyze_url(request: URLRequest):
    url = request.url.strip(' "\'\n\r')
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    try:
        # --- 1. Machine Learning Prediction ---
        features = extract_features(url)
        handcrafted_df = pd.DataFrame([features])

        cleaned_url = re.sub(r"^https?://(www\.)?", "", url.lower())
        tfidf_matrix = vectorizer.transform([cleaned_url])
        tfidf_cols = [f"tfidf_{name}" for name in vectorizer.get_feature_names_out()]
        tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=tfidf_cols)

        full_features = pd.concat([handcrafted_df, tfidf_df], axis=1)

        raw_prediction = int(model.predict(full_features)[0])
        probabilities = model.predict_proba(full_features)[0]

        legit_prob = float(probabilities[0])
        phish_prob = float(probabilities[1])

        # --- 2. Live Domain Analysis & Trust Heuristics ---
        network_info = get_extended_domain_info(url)
        domain_age_days = network_info["age_days"] if network_info else None
        
        is_new_domain = False
        
        if domain_age_days is not None:
            # Rule 1: Flag as suspicious if < 30 days old
            if domain_age_days < 30:
                is_new_domain = True
                # Penalize new domains: Boost phishing probability by 25%
                phish_prob = min(0.95, phish_prob + 0.25)
                
            # Rule 2: High trust for domains > 10 years old (e.g., Google, GitHub)
            elif domain_age_days > 3650:
                # Slash phishing probability by 40%
                phish_prob = max(0.01, phish_prob - 0.40)
                
            # Rule 3: Medium-High trust for domains > 3 years old
            elif domain_age_days > 1095:
                # Slash phishing probability by 20%
                phish_prob = max(0.01, phish_prob - 0.20)
                
            # Rule 4: Moderate trust for domains > 1 year old
            elif domain_age_days > 365:
                phish_prob = max(0.01, phish_prob - 0.10)

        spoofed_brand = check_brand_spoofing(url)
        if spoofed_brand:
            phish_prob = min(0.99, phish_prob + 0.40) # Huge penalty for brand spoofing

        # Rule 6: High Entropy (Randomness in the domain)
        parsed_url = urlparse(url)
        domain_entropy = calculate_entropy(parsed_url.hostname or "")
        high_entropy = domain_entropy > 4.0
        if high_entropy:
            phish_prob = min(0.95, phish_prob + 0.15) # Penalty for looking randomly generated
            
        # Rule 7: High Digit Ratio
        digit_ratio = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
        high_digits = digit_ratio > 0.15
        if high_digits:
            phish_prob = min(0.95, phish_prob + 0.10) # Penalty for too many numbers

        # Recalculate legit prob and final prediction
        legit_prob = 1.0 - phish_prob
        final_prediction = 1 if phish_prob > 0.5 else 0

        # --- 3. Return Combined JSON ---
        return {
            "url": url,
            "is_phishing": bool(final_prediction == 1),
            "phishing_probability": round(phish_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "network": network_info, # <-- Make sure this line is here!
            "flags": {
                "suspicious_new_domain": is_new_domain,
                "spoofed_brand": spoofed_brand,
                "high_entropy": high_entropy,
                "high_digits": high_digits
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)