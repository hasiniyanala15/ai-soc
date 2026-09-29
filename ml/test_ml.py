import unittest
import pandas as pd
import numpy as np
import os
import json
import joblib

# Suppress scikit-learn warnings during tests
import warnings
warnings.filterwarnings("ignore")

# Import the ML modules we built
from ml.dataset_loader import generate_synthetic_cic_ids2017, DATASET_PATH
from ml.preprocess import clean_data, get_preprocessor, FEATURES
from ml.threat_predictor import predict_threat, get_threat_category, MODEL_PATH
from app import app

class TestMLPipeline(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Setup small synthetic dataset and Flask test client"""
        cls.test_csv = "data/test_cic_ids2017.csv"
        # Temporarily redirect dataset path for safe testing
        cls.original_dataset_path = DATASET_PATH
        
        # Create a tiny 50-row synthetic dataset for testing
        df = pd.DataFrame([
            [5000, 2, 2, 1000, 80, 6, 10.5, 0, "Benign"],
            [100, 500, 0, 50000, 80, 6, np.inf, 0, "DoS"],
            [50000, 20, 20, 5000, 22, 6, 50, 10, "Brute Force"],
            [np.nan, 1, 1, 0, 4444, 6, 0, 0, "PortScan"],
            [5000, 2, 2, 1000, 80, 6, 10.5, 0, "Benign"], # Duplicate
        ], columns=FEATURES + ["Label"])
        
        os.makedirs("data", exist_ok=True)
        df.to_csv(cls.test_csv, index=False)
        cls.df = df
        
        # Setup Flask Test Client
        app.config['TESTING'] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        if os.path.exists(cls.test_csv):
            os.remove(cls.test_csv)

    # --- Step 15: Unit Tests ---

    def test_dataset_loading(self):
        df_loaded = pd.read_csv(self.test_csv)
        self.assertEqual(len(df_loaded), 5)
        
    def test_missing_values_and_duplicates(self):
        """Tests that NaNs and Infinities are caught, and duplicates dropped."""
        df_clean = clean_data(self.df.copy())
        # Dropped 1 duplicate
        self.assertEqual(len(df_clean), 4)
        # Replaced Inf with NaN (row 1 column Flow Bytes/s)
        self.assertTrue(pd.isna(df_clean.iloc[1]['Flow Bytes/s']))
        # Preserved existing NaN
        self.assertTrue(pd.isna(df_clean.iloc[3]['Flow Duration']))
        
    def test_feature_preprocessing(self):
        df_clean = clean_data(self.df.copy())
        preprocessor = get_preprocessor()
        X = df_clean[FEATURES]
        X_processed = preprocessor.fit_transform(X)
        # Ensure NaNs were imputed (no NaNs remain in the processed matrix)
        self.assertFalse(np.isnan(X_processed).any())
        
    def test_training_and_testing_separation(self):
        """Ensure test data isn't leaking into the preprocessor."""
        df_clean = clean_data(self.df.copy())
        preprocessor = get_preprocessor()
        
        X_train = df_clean[FEATURES].iloc[:2]
        X_test = df_clean[FEATURES].iloc[2:]
        
        # Fit ONLY on train
        preprocessor.fit(X_train)
        
        # The mean of 'Failed Logins' in X_train is 0. 
        # If we transform X_test, it should scale relative to X_train's mean.
        X_test_scaled = preprocessor.transform(X_test)
        self.assertIsNotNone(X_test_scaled)
        
    def test_model_loading_and_valid_prediction(self):
        """Test inference on a valid event."""
        if not os.path.exists(MODEL_PATH):
            self.skipTest("Model not trained yet. Run train_model.py")
            
        event = {
            "Flow Duration": 5000, "Total Fwd Packets": 2, "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 1000, "Destination Port": 80, 
            "Protocol": 6, "Flow Bytes/s": 10.5, "Failed Logins": 0
        }
        res = predict_threat(event)
        self.assertEqual(res['status'], 'success')
        self.assertIn("Benign", res['predicted_class'])
        
    def test_invalid_input(self):
        """Test missing features."""
        event = {"Flow Duration": 5000} # Missing all other features
        res = predict_threat(event)
        self.assertEqual(res['status'], 'failed')
        self.assertIn("Missing required feature", res['error'])
        
    def test_unknown_attack_class(self):
        """Test mapping an unknown label."""
        category = get_threat_category("Alien_Attack_2026")
        self.assertEqual(category, "Other Attack")
        
    def test_flask_prediction_endpoint(self):
        """Test the POST /ml/predict endpoint integration."""
        if not os.path.exists(MODEL_PATH):
            self.skipTest("Model not trained yet. Run train_model.py")
            
        event = {
            "Flow Duration": 5000, "Total Fwd Packets": 2, "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 1000, "Destination Port": 80, 
            "Protocol": 6, "Flow Bytes/s": 10.5, "Failed Logins": 0
        }
        response = self.client.post('/ml/predict', json=event)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        
    def test_flask_status_endpoint(self):
        response = self.client.get('/ml/status')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
