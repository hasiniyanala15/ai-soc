import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
import os

from dataset_loader import load_dataset
from preprocess import clean_data, FEATURES, TARGET_COLUMN

MODEL_PATH = "models/model.joblib"
PREPROCESSOR_PATH = "models/preprocessor.joblib"
REPORT_PATH = "reports/classification_report.txt"
MATRIX_PATH = "reports/confusion_matrix.png"

def evaluate_model():
    """
    Step 8: Model Evaluation
    Loads the reserved Testing dataset (which the model has NEVER seen),
    and evaluates its performance using advanced cybersecurity metrics.
    """
    print("Loading test dataset and model...")
    df = load_dataset()
    df = clean_data(df)
    
    # We must split the data EXACTLY the same way we did in train_model.py
    # to extract the reserved Testing set.
    X = df[FEATURES]
    y = df[TARGET_COLUMN]
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    
    try:
        model = joblib.load(MODEL_PATH)
        preprocessor = joblib.load(PREPROCESSOR_PATH)
    except FileNotFoundError:
        print("Error: Model or Preprocessor not found. Run train_model.py first.")
        return

    # Process the test data using the fitted preprocessor
    X_test_processed = preprocessor.transform(X_test)
    
    # Make predictions
    predictions = model.predict(X_test_processed)
    
    # 1. Global Metrics
    acc = accuracy_score(y_test, predictions)
    print(f"\n--- Global Metrics ---")
    print(f"Accuracy: {acc:.4f} (Do not rely solely on this due to class imbalance!)")
    
    # 2. Per-class Classification Report
    # We use this to see Precision, Recall, and F1-Score for EACH attack category separately.
    report = classification_report(y_test, predictions)
    print(f"\n--- Classification Report ---")
    print(report)
    
    # Save the report
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        f.write("--- Cybersecurity ML Evaluation Report ---\n\n")
        f.write(report)
        f.write("\n\nWhy these metrics matter in Cybersecurity:\n")
        f.write("- Precision (High False Positives): If precision is low, the AI will spam analysts with fake alerts, causing Alert Fatigue.\n")
        f.write("- Recall (High False Negatives): If recall is low, the AI will miss actual hackers slipping through the network. In cybersecurity, we generally prioritize RECALL for malicious classes over precision.\n")
        
    # 3. Confusion Matrix (Calculates Exact FP and FN rates)
    cm = confusion_matrix(y_test, predictions, labels=model.classes_)
    
    print("\n--- False Positive / False Negative Breakdown ---")
    for i, class_name in enumerate(model.classes_):
        # True Positives: Diagonal element
        tp = cm[i, i]
        # False Positives: Sum of the column minus TP
        fp = cm[:, i].sum() - tp
        # False Negatives: Sum of the row minus TP
        fn = cm[i, :].sum() - tp
        # True Negatives: Sum of whole matrix minus (TP + FP + FN)
        tn = cm.sum() - (tp + fp + fn)
        
        # Calculate Rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        print(f"[{class_name}] False Positive Rate: {fpr:.4f} | False Negative Rate: {fnr:.4f}")
        
    # 4. Generate visual matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=model.classes_, yticklabels=model.classes_)
    plt.ylabel('Actual Label (Ground Truth)')
    plt.xlabel('Predicted Label (AI Output)')
    plt.title('Threat Detection Confusion Matrix')
    plt.savefig(MATRIX_PATH)
    print(f"\nArtifacts saved:")
    print(f" - {REPORT_PATH}")
    print(f" - {MATRIX_PATH}")
    
    print("\nWARNING: Performance on this static public dataset does not guarantee identical performance on real-world live network traffic. Networks experience 'Concept Drift' over time.")

if __name__ == "__main__":
    evaluate_model()
