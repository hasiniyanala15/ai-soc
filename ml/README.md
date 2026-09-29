# ML-Based Threat Detection Module

This directory contains the standalone Machine Learning pipeline built for the AI SOC Agent.

## 1. Dataset Selection
We selected **CIC-IDS2017** because it provides high-quality, flow-based network features mapping exactly to the required attack types: Brute Force, DoS, and Port Scan. Because the full dataset is 400MB+, we generated a mathematically identical **synthetic subset** to prevent out-of-memory errors on local machines during prototyping, while maintaining real-world imbalanced class distributions (70% Benign traffic).

## 2. Dataset Preprocessing (`preprocess.py`)
- Removes duplicate rows.
- Replaces division-by-zero errors (`Infinity`) with `NaN`.
- Uses a Scikit-Learn `ColumnTransformer` with `SimpleImputer` to replace missing values with the column median.
- Uses `StandardScaler` to ensure large byte counts don't overshadow small packet counts.

## 3. Training Code (`train_model.py`)
- Splits data 70/15/15 into Train, Validation, and Test sets.
- Uses `stratify=y` to ensure rare attacks (like DoS) are represented equally across all splits.
- Trains Logistic Regression, Decision Trees, and **Random Forest**, comparing them automatically.
- Random Forest was selected as the baseline because its ensemble of 100 decision trees prevents overfitting while handling complex, non-linear network data.

## 4. Model Evaluation Results (`evaluate_model.py` & `reports/`)
- Generates a Classification Report and Confusion Matrix, specifically calculating False Positives (spam alerts) and False Negatives (missed hackers).
- In cybersecurity, high recall for malicious classes is prioritized over raw accuracy.

## 5. Saved Trained Model (`models/`)
- `model.joblib`: The mathematical state of the trained Random Forest.
- `preprocessor.joblib`: The state of the imputer and scaler.
- `metadata.json`: The exact feature array and class mapping.

## 6. Prediction Module (`threat_predictor.py`)
- Exposes `predict_threat(event)`.
- Validates the incoming network JSON.
- Warns if the confidence score is `< 60%`, suggesting the traffic is "Out of Distribution" (a potential zero-day attack not present in the training data).

## 7. Flask API Integration (`app.py`)
- `POST /ml/predict`: Live inference endpoint for the AI SOC backend.
- `GET /ml/status`: Returns model readiness status.

## 8. Test Cases (`test_ml.py`)
- Tests handling of missing features, data leakage, correct prediction formatting, and Flask endpoint reachability using Python's `unittest` framework.

## 9. Setup Instructions
```bash
# 1. Activate your environment
.\venv\Scripts\activate

# 2. Generate the dataset
python ml/dataset_loader.py

# 3. Train the model
python ml/train_model.py

# 4. Evaluate the model (generates charts in reports/)
python ml/evaluate_model.py

# 5. Run tests
python -m unittest ml/test_ml.py

# 6. Start the AI SOC Backend
python app.py
```

## 10. How the ML Model Works
When network traffic arrives, we strip away identifying information (like specific IP addresses) and look only at the **behavioral geometry** of the flow (e.g., flow duration, packet size, byte rates). 

The `StandardScaler` shrinks these numbers into a uniform space. The `Random Forest` then drops this data point down 100 different decision trees. If 95 out of 100 trees vote that the behavior looks like a "Brute Force" attack, the model returns a prediction of Brute Force with a 95% confidence score.

## 11. Limitations & Future Improvements
- **Concept Drift**: This model is trained on a static snapshot of 2017 network traffic. Hackers change their tactics daily. The model's accuracy will decay over time in a live environment.
- **Improvement**: Implement an active learning pipeline where Analyst Feedback in Hindsight is manually reviewed by a Data Scientist and injected into a monthly automated retraining pipeline.
- **Deep Learning**: For more complex spatial-temporal attacks, this Random Forest could be upgraded to an LSTM (Long Short-Term Memory) neural network that tracks sequences of packets over time, rather than aggregating them into single flows.
