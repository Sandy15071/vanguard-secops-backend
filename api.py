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
TRUSTED_TLDS = [".gov.in", ".gov", ".nic.in", ".edu", ".mil", ".ac.in", ".edu.in"]

def calculate_entropy(text):
    if not text: 
        return 0
    entropy = 0
    for x in Counter(text).values():
        p_x = float(x) / len(text)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def check_brand_spoofing(url):
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    
    for brand in TARGET_BRANDS:
        if brand in hostname:
            if hostname == f"{brand}.com" or hostname == f"www.{brand}.com":
                continue
            return brand.capitalize()
    return None

app = FastAPI(
    title="Phishing URL Detector API",
    description="An API to analyze URLs and return phishing risk probabilities.",
    version="1.0.0"
)

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://vanguard-secops-frontend.vercel.app",
    "https://vanguard-secops.vercel.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_FILE = "model/compressed_model.pkl"
VECTORIZER_FILE = "model/tfidf_vectorizer.pkl"

try:
    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)
except Exception as e:
    print(f"Error loading model artifacts: {e}")

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
        parsed_url = urlparse(url)
        hostname = (parsed_url.hostname or "").lower()

        network_info = get_extended_domain_info(url)

        if any(hostname.endswith(tld) for tld in TRUSTED_TLDS):
            return {
                "url": url,
                "is_phishing": False,
                "phishing_probability": 0.0,
                "legitimate_probability": 1.0,
                "network": network_info,
                "flags": {
                    "suspicious_new_domain": False,
                    "spoofed_brand": None,
                    "high_entropy": False,
                    "high_digits": False
                }
            }

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

        domain_age_days = network_info["age_days"] if network_info else None
        
        is_new_domain = False
        
        if domain_age_days is not None:
            if domain_age_days < 30:
                is_new_domain = True
                phish_prob = min(0.95, phish_prob + 0.25)
            elif domain_age_days > 3650:
                phish_prob = max(0.01, phish_prob - 0.40)
            elif domain_age_days > 1095:
                phish_prob = max(0.01, phish_prob - 0.20)
            elif domain_age_days > 365:
                phish_prob = max(0.01, phish_prob - 0.10)

        spoofed_brand = check_brand_spoofing(url)
        if spoofed_brand:
            phish_prob = min(0.99, phish_prob + 0.40)

        domain_entropy = calculate_entropy(hostname)
        high_entropy = domain_entropy > 4.0
        if high_entropy:
            phish_prob = min(0.95, phish_prob + 0.15)
            
        digit_ratio = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
        high_digits = digit_ratio > 0.15
        if high_digits:
            phish_prob = min(0.95, phish_prob + 0.10)

        legit_prob = 1.0 - phish_prob
        final_prediction = 1 if phish_prob > 0.5 else 0

        return {
            "url": url,
            "is_phishing": bool(final_prediction == 1),
            "phishing_probability": round(phish_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "network": network_info,
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