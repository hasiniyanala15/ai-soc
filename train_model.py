import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DATABASE_PATH", "data/soc_agent.db").replace("sqlite:///", "")
MODEL_PATH = 'data/ml_model.pkl'

def extract_features(df):
    """
    Transforms raw logs into numerical features for ML.
    We extract temporal anomalies (like impossible travel) and frequency anomalies (brute force).
    """
    # Sort chronologically to calculate time deltas
    df = df.sort_values(by='timestamp').copy()
    
    # 1. Parse timestamps cleanly
    def parse_ts(t):
        if isinstance(t, str):
            t = t.replace('Z', '+00:00')
            try:
                return datetime.fromisoformat(t).replace(tzinfo=None)
            except ValueError:
                return datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S")
        return t
        
    df['ts_parsed'] = df['timestamp'].apply(parse_ts)
    
    # 2. Base feature: is it a failure?
    df['is_failed'] = (df['login_status'] == 'FAILED').astype(int)
    
    # 3. User-based features (for Impossible Travel)
    # Calculate time since this user last logged in
    df['prev_user_ts'] = df.groupby('username')['ts_parsed'].shift(1)
    df['prev_user_ip'] = df.groupby('username')['source_ip'].shift(1)
    
    df['seconds_since_last_user_login'] = (df['ts_parsed'] - df['prev_user_ts']).dt.total_seconds().fillna(86400)
    # If the IP changed from the last login for this user, flag it (1), else (0)
    df['user_ip_changed'] = (df['source_ip'] != df['prev_user_ip']).astype(int)
    # Give a very high penalty if IP changed and time is incredibly short (Impossible Travel)
    df['impossible_travel_score'] = df.apply(
        lambda row: 1000 if row['user_ip_changed'] == 1 and row['seconds_since_last_user_login'] < 3600 else 0, 
        axis=1
    )
    
    # 4. IP-based features (for Brute Force and Low & Slow)
    df['prev_ip_ts'] = df.groupby('source_ip')['ts_parsed'].shift(1)
    df['seconds_since_last_ip_login'] = (df['ts_parsed'] - df['prev_ip_ts']).dt.total_seconds().fillna(86400)
    
    # Rolling count of failures for this IP in the last 2 hours
    # (Since we can't easily do rolling on datetime index without setting it, we'll approximate it by grouping by IP and taking a rolling sum of is_failed)
    # A simplified feature: just count how many failures this IP has had overall in this dataset
    ip_failure_counts = df.groupby('source_ip')['is_failed'].transform('sum')
    df['ip_total_failures'] = ip_failure_counts
    
    # Final feature set for the ML model
    features = [
        'is_failed',
        'seconds_since_last_user_login',
        'impossible_travel_score',
        'seconds_since_last_ip_login',
        'ip_total_failures'
    ]
    
    return df, features

def train_isolation_forest():
    print("Connecting to database to fetch training data...")
    if not os.path.exists(DB_PATH):
        print(f"Error: Database {DB_PATH} not found. Generate logs first.")
        return False
        
    conn = sqlite3.connect(DB_PATH)
    # Load recent logs (we'll take up to 10,000 for training)
    df = pd.read_sql_query("SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 10000", conn)
    conn.close()
    
    if len(df) < 50:
        print("Not enough logs to train a reliable model. Need at least 50.")
        return False
        
    print(f"Loaded {len(df)} logs. Engineering features...")
    df, feature_cols = extract_features(df)
    
    X = df[feature_cols].fillna(0)
    
    print("Training Isolation Forest ML model...")
    # Isolation forest detects anomalies by randomly partitioning data. 
    # Outliers (attacks) are easier to isolate than normal behavior.
    model = IsolationForest(
        n_estimators=100, 
        contamination=0.05, # Expect about 5% of logs to be anomalies
        random_state=42
    )
    
    model.fit(X)
    
    # Save the model
    os.makedirs('data', exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[SUCCESS] ML Model trained and saved to {MODEL_PATH}")
    
    # Let's see what it flagged in our training data
    df['anomaly'] = model.predict(X)
    anomalies = df[df['anomaly'] == -1]
    print(f"Model identified {len(anomalies)} anomalous logs in the training set.")
    
    return True

if __name__ == "__main__":
    train_isolation_forest()
