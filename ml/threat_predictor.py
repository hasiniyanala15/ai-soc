import joblib
import pandas as pd
import numpy as np
import json
import os

MODEL_PATH = "models/model.joblib"
PREPROCESSOR_PATH = "models/preprocessor.joblib"
METADATA_PATH = "models/metadata.json"

# Load global instances to avoid loading from disk on every single prediction (important for speed)
_model = None
_preprocessor = None
_metadata = None

def _load_artifacts():
    global _model, _preprocessor, _metadata
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError("Model not found. Please train the model first.")
        _model = joblib.load(MODEL_PATH)
        _preprocessor = joblib.load(PREPROCESSOR_PATH)
        with open(METADATA_PATH, 'r') as f:
            _metadata = json.load(f)

def get_threat_category(predicted_label):
    """
    Step 10: Threat Classification
    Maps the raw dataset label to a standard SOC category.
    """
    mapping = {
        "Benign": "Benign",
        "Brute Force": "Brute Force",
        "DoS": "DoS or DDoS",
        "PortScan": "Port Scan"
    }
    return mapping.get(predicted_label, "Other Attack")

def predict_threat(event_dict):
    """
    Step 9: Model Prediction Module
    Accepts a single security event (dictionary), validates it, preprocesses it, 
    and predicts the threat class.
    """
    try:
        _load_artifacts()
    except Exception as e:
        return {"error": str(e), "status": "failed"}
        
    expected_features = _metadata["features"]
    
    # 1. Validate Input
    # Ensure all expected features are present in the incoming event
    for feature in expected_features:
        if feature not in event_dict:
            return {
                "error": f"Missing required feature: '{feature}'", 
                "status": "failed"
            }
            
    # 2. Format as a DataFrame for the preprocessor
    # We must match the exact format used during training
    try:
        df_event = pd.DataFrame([event_dict])[expected_features]
    except Exception as e:
        return {"error": f"Invalid data format: {e}", "status": "failed"}
        
    # Check for unexpected/unsupported data types
    try:
        df_event = df_event.astype(float)
    except ValueError:
        return {"error": "All features must be numeric", "status": "failed"}

    # 3. Apply Preprocessing Pipeline
    try:
        X_processed = _preprocessor.transform(df_event)
    except Exception as e:
        return {"error": f"Preprocessing failed: {e}", "status": "failed"}
        
    # 4. Predict Class and Confidence
    predicted_label = _model.predict(X_processed)[0]
    
    # Get confidence (if supported by model)
    # Random Forest supports predict_proba. 
    # Note: This is tree voting percentage, NOT true calibrated probability.
    try:
        probabilities = _model.predict_proba(X_processed)[0]
        class_index = list(_model.classes_).index(predicted_label)
        confidence_score = float(probabilities[class_index])
    except AttributeError:
        confidence_score = None
        
    # 5. Out of distribution warning
    # Simple heuristic: If confidence is very low, it might be an unknown attack
    warning = None
    if confidence_score is not None and confidence_score < 0.6:
        warning = "Low confidence prediction. Event may be outside the training data distribution (Unknown Attack)."

    # 6. Structure the result
    return {
        "predicted_class": predicted_label,
        "threat_category": get_threat_category(predicted_label),
        "confidence_score": confidence_score,
        "model_version": _metadata.get("version", "unknown"),
        "warning": warning,
        "status": "success",
        "processed_features": df_event.to_dict(orient="records")[0]
    }

if __name__ == "__main__":
    # Quick Test
    test_event_benign = {
        "Flow Duration": 5000, "Total Fwd Packets": 2, "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 1000, "Destination Port": 80, 
        "Protocol": 6, "Flow Bytes/s": 10.5, "Failed Logins": 0
    }
    
    test_event_attack = {
        "Flow Duration": 100, "Total Fwd Packets": 500, "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 50000, "Destination Port": 80, 
        "Protocol": 6, "Flow Bytes/s": 5000, "Failed Logins": 0
    }
    
    print("Testing Benign Event:")
    print(json.dumps(predict_threat(test_event_benign), indent=2))
    
    print("\nTesting Attack Event:")
    print(json.dumps(predict_threat(test_event_attack), indent=2))
