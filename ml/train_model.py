import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import json

try:
    from .dataset_loader import load_dataset
    from .preprocess import clean_data, get_preprocessor, FEATURES, TARGET_COLUMN
except ImportError:
    from dataset_loader import load_dataset
    from preprocess import clean_data, get_preprocessor, FEATURES, TARGET_COLUMN

MODEL_PATH = "models/model.joblib"
PREPROCESSOR_PATH = "models/preprocessor.joblib"
METADATA_PATH = "models/metadata.json"

def train_and_compare():
    """
    Step 6 & 7: Model Selection and Training
    Splits the data, trains 3 different models, compares them, 
    and saves the best baseline (Random Forest) along with the preprocessor.
    """
    print("Loading and cleaning dataset...")
    df = load_dataset()
    df = clean_data(df)
    
    # 2. Separate features and labels
    X = df[FEATURES]
    y = df[TARGET_COLUMN]
    
    # 3. Split the data into Training (70%), Validation (15%), and Testing (15%)
    # Stratify=y ensures that the imbalanced classes are distributed equally across all sets
    print("\nSplitting dataset (preventing data leakage)...")
    X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.1765, stratify=y_temp, random_state=42) # 0.1765 of 0.85 is ~0.15
    
    print(f"Training set: {len(X_train)} records")
    print(f"Validation set: {len(X_val)} records")
    print(f"Testing set: {len(X_test)} records (Reserved for final evaluation)")
    
    # 4. Fit the preprocessor ONLY on the training data
    print("\nFitting preprocessing pipeline...")
    preprocessor = get_preprocessor()
    X_train_processed = preprocessor.fit_transform(X_train)
    X_val_processed = preprocessor.transform(X_val)
    
    # 5. Define the models to compare
    # We use class_weight='balanced' to handle the class imbalance (70% Benign)
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
        "Decision Tree": DecisionTreeClassifier(class_weight='balanced', random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    }
    
    best_model_name = ""
    best_model = None
    best_accuracy = 0
    
    # 6. Train and Evaluate each model on the Validation Set
    print("\nTraining and comparing models:")
    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X_train_processed, y_train)
        
        # Predict on validation set to find the best model
        val_predictions = model.predict(X_val_processed)
        acc = accuracy_score(y_val, val_predictions)
        print(f" > {name} Validation Accuracy: {acc:.4f}")
        
        if acc > best_accuracy:
            best_accuracy = acc
            best_model_name = name
            best_model = model
            
    print(f"\n[WINNER] Selected {best_model_name} as the final model with {best_accuracy:.4f} accuracy.")
    
    # 7 & 8. Save the selected model and preprocessor
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)
    
    # 9. Save the feature names and class labels for prediction time
    metadata = {
        "features": FEATURES,
        "classes": list(best_model.classes_),
        "model_type": best_model_name,
        "version": "1.0"
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=4)
        
    print(f"\nArtifacts saved successfully:")
    print(f" - Model: {MODEL_PATH}")
    print(f" - Preprocessor: {PREPROCESSOR_PATH}")
    print(f" - Metadata: {METADATA_PATH}")

if __name__ == "__main__":
    train_and_compare()
