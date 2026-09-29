import json
import uuid
import random
from datetime import datetime, timedelta, timezone
import os
from database import insert_log, init_db

# Fictional users and documentation IP addresses (safe to use)
USERS = ["admin", "jsmith", "jdoe", "service_account", "guest"]
NORMAL_IPS = ["192.0.2.15", "192.0.2.42", "203.0.113.5", "203.0.113.10"]
ATTACKER_IP = "198.51.100.99"

def generate_logs(num_normal=100, generate_brute_force=True, generate_ml_attacks=True):
    """Generates sample authentication logs including advanced ML attacks."""
    logs = []
    
    # Generate normal traffic
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)
    
    for _ in range(num_normal):
        timestamp = base_time + timedelta(minutes=random.randint(1, 55))
        logs.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "event_type": "authentication",
            "username": random.choice(USERS),
            "source_ip": random.choice(NORMAL_IPS),
            "login_status": random.choices(["SUCCESS", "FAILED"], weights=[80, 20])[0]
        })
        
    # Generate a brute-force attack (12 failed attempts from one IP in a short window)
    if generate_brute_force:
        attack_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        for i in range(12):
            # Rapid attempts (every 5-10 seconds)
            timestamp = attack_time + timedelta(seconds=(i * random.randint(5, 10)))
            logs.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": timestamp.isoformat(),
                "event_type": "authentication",
                "username": "admin", # Targeting admin
                "source_ip": ATTACKER_IP,
                "login_status": "FAILED"
            })
            
    # Generate advanced ML attacks
    if generate_ml_attacks:
        ml_attack_time = datetime.now(timezone.utc) - timedelta(hours=2)
        
        # Attack 1: Low and Slow Spraying (bypasses threshold rules)
        # e.g., 8 attempts across 2 hours (less than 10 in 2 minutes)
        for i in range(8):
            ts = ml_attack_time + timedelta(minutes=(i * 15))
            logs.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts.isoformat(),
                "event_type": "authentication",
                "username": random.choice(USERS),
                "source_ip": "203.0.113.99", # Threat actor IP
                "login_status": "FAILED"
            })
            
        # Attack 2: Impossible Travel (Successful login from normal IP, then successful login from foreign IP minutes later)
        normal_user = "jsmith"
        it_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        logs.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": it_time.isoformat(),
            "event_type": "authentication",
            "username": normal_user,
            "source_ip": "192.0.2.15", # Normal
            "login_status": "SUCCESS"
        })
        logs.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": (it_time + timedelta(minutes=5)).isoformat(),
            "event_type": "authentication",
            "username": normal_user,
            "source_ip": "100.200.50.1", # Malicious foreign IP
            "login_status": "SUCCESS"
        })
            
    # Sort logs chronologically
    logs.sort(key=lambda x: x['timestamp'])
    
    # Save to JSON file for inspection
    os.makedirs("data", exist_ok=True)
    with open("data/security_logs.json", "w") as f:
        json.dump(logs, f, indent=4)
        
    # Insert into the database
    init_db() # Ensure DB exists
    for log in logs:
        insert_log(log)
        
    print(f"Generated {len(logs)} logs and saved them to the database and data/security_logs.json")
    return logs

if __name__ == "__main__":
    generate_logs()
