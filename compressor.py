import joblib
import os

old_model_name = "model/phishing_model.pkl" 
new_model_name = "compressed_model.pkl"

print(f"Loading uncompressed model ({os.path.getsize(old_model_name) / (1024*1024):.1f} MB)...")

model = joblib.load(old_model_name)

print("Compressing and saving...")
joblib.dump(model, new_model_name, compress=3)

print(f"Success! New model size: {os.path.getsize(new_model_name) / (1024*1024):.1f} MB")