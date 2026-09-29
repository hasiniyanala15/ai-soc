import os
from datetime import datetime, timedelta
from database import get_recent_logs, create_alert
from dotenv import load_dotenv
import pandas as pd
import joblib

load_dotenv()

# Load configurable rules from .env
THRESHOLD = int(os.getenv("DETECTION_THRESHOLD", 10))
TIME_WINDOW_MINS = int(os.getenv("DETECTION_TIME_WINDOW_MINUTES", 2))

def detect_brute_force(logs):
    """
    Analyzes a list of security logs and detects brute-force attacks.
    Returns a list of generated alert IDs.
    """
    failed_attempts_by_ip = {}
    
    # 1. Group all FAILED attempts by IP address
    for log in logs:
        if log['login_status'] == 'FAILED':
            ip = log['source_ip']
            if ip not in failed_attempts_by_ip:
                failed_attempts_by_ip[ip] = []
            
            # Cleanly parse the timestamp
            try:
                ts = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00')).replace(tzinfo=None)
            except ValueError:
                ts = datetime.strptime(log['timestamp'][:19], "%Y-%m-%dT%H:%M:%S")
                
            failed_attempts_by_ip[ip].append({
                "timestamp": ts,
                "event_id": log['event_id'],
                "username": log['username']
            })

    alerts_created = []

    # 2. Check each IP against the threshold rules
    for ip, attempts in failed_attempts_by_ip.items():
        # Ensure they are sorted from oldest to newest
        attempts.sort(key=lambda x: x['timestamp'])
        
        # Sliding time window logic
        for i in range(len(attempts)):
            window_start = attempts[i]['timestamp']
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINS)
            
            # Find all failures inside this specific 2-minute window
            failures_in_window = []
            for j in range(i, len(attempts)):
                if attempts[j]['timestamp'] <= window_end:
                    failures_in_window.append(attempts[j])
                else:
                    # We've moved past the 2-minute window, stop looking
                    break
                    
            # 3. If failures reach our threshold (10), trigger an alert!
            if len(failures_in_window) >= THRESHOLD:
                evidence = {
                    "reason": f"Detected {len(failures_in_window)} failed logins within {TIME_WINDOW_MINS} minutes.",
                    "failed_count": len(failures_in_window),
                    "first_attempt": failures_in_window[0]['timestamp'].isoformat(),
                    "last_attempt": failures_in_window[-1]['timestamp'].isoformat(),
                    # Collect all unique usernames the attacker tried to guess
                    "targeted_usernames": list(set([a['username'] for a in failures_in_window])) 
                }
                
                # Determine severity based on volume
                severity = "MEDIUM"
                if len(failures_in_window) >= THRESHOLD * 2:
                    severity = "HIGH"
                    
                # Save the alert into the SQLite Database
                alert_id = create_alert(
                    alert_type="brute_force",
                    severity=severity,
                    source_ip=ip,
                    evidence=evidence
                )
                
                if alert_id: # Will be None if we already created an alert for this IP recently
                    alerts_created.append(alert_id)
                    print(f"[ALERT] Brute-force detected from {ip}. Alert ID: {alert_id}")
                
                # Stop checking this IP to prevent creating 100 alerts for the same continuous attack
                break 

    return alerts_created

def run_detection():
    """Main function to grab logs from DB and run the detector."""
    print("Fetching logs from database...")
    logs = get_recent_logs()
    print(f"Analyzing {len(logs)} logs...")
    
    alerts = detect_brute_force(logs)
    
    # Run Advanced ML Detection if model is trained
    ml_alerts = detect_anomalies_ml(logs)
    alerts.extend(ml_alerts)
    
    if not alerts:
        print("[SAFE] No threats detected by rules or ML.")
        
    return alerts

def detect_anomalies_ml(logs):
    """
    Passes recent logs through the trained Isolation Forest ML model.
    """
    model_path = 'data/ml_model.pkl'
    if not os.path.exists(model_path):
        return []
        
    try:
        model = joblib.load(model_path)
    except Exception as e:
        print(f"Failed to load ML model: {e}")
        return []
        
    # Import extract_features dynamically to avoid circular imports if any
    try:
        from train_model import extract_features
    except ImportError:
        return []

    # Convert logs to DataFrame
    df = pd.DataFrame(logs)
    if df.empty:
        return []
        
    # Extract features
    try:
        df_features, feature_cols = extract_features(df)
        X = df_features[feature_cols].fillna(0)
    except Exception as e:
        print(f"ML Feature extraction failed: {e}")
        return []
        
    # Predict (-1 is anomaly, 1 is normal)
    predictions = model.predict(X)
    df_features['anomaly'] = predictions
    
    anomalies = df_features[df_features['anomaly'] == -1]
    
    alerts_created = []
    
    # Group anomalies by IP so we don't spam alerts
    for ip, group in anomalies.groupby('source_ip'):
        # Check if we have impossible travel or low and slow
        has_impossible_travel = (group['impossible_travel_score'] > 0).any()
        
        attack_type = "impossible_travel" if has_impossible_travel else "ml_anomaly_detected"
        
        evidence = {
            "reason": f"Machine Learning Isolation Forest flagged {len(group)} anomalous events from this IP.",
            "attack_signature": attack_type,
            "anomaly_score_confidence": "High", # Simplified
            "flagged_logs": group[['timestamp', 'username', 'login_status']].to_dict(orient='records')
        }
        
        # Determine severity for ML
        severity = "LOW"
        if attack_type == "impossible_travel":
            severity = "HIGH"
        elif len(group) > 5:
            severity = "MEDIUM"
            
        alert_id = create_alert(
            alert_type=attack_type,
            severity=severity,
            source_ip=ip,
            evidence=evidence
        )
        
        if alert_id:
            alerts_created.append(alert_id)
            print(f"[ML ALERT] {attack_type} detected from {ip}. Alert ID: {alert_id}")
            
    return alerts_created

if __name__ == "__main__":
    run_detection()
