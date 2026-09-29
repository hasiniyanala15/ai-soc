import sqlite3
import json
import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load configuration from .env
load_dotenv()

# Extract database path safely (removing sqlite:/// prefix if present)
db_env = os.getenv("DATABASE_PATH", "data/soc_agent.db")
DB_PATH = db_env.replace("sqlite:///", "")

def get_connection():
    """Create and return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    # This allows us to access columns by name (like a dictionary)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create all necessary tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Security Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE,
            timestamp TEXT,
            event_type TEXT,
            username TEXT,
            source_ip TEXT,
            login_status TEXT
        )
    ''')
    
    # 2. Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            evidence TEXT,
            created_at TEXT
        )
    ''')
    
    # 3. Investigation Reports Table (Linked to Alerts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER UNIQUE,
            summary TEXT,
            attack_type TEXT,
            confidence TEXT,
            recommended_action TEXT,
            created_at TEXT,
            FOREIGN KEY(alert_id) REFERENCES alerts(id)
        )
    ''')
    
    # 4. Analyst Feedback Table (Linked to Alerts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER UNIQUE,
            analyst_notes TEXT,
            was_helpful BOOLEAN,
            created_at TEXT,
            FOREIGN KEY(alert_id) REFERENCES alerts(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def insert_log(log_data):
    """Insert a single security log into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO security_logs (event_id, timestamp, event_type, username, source_ip, login_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            log_data['event_id'],
            log_data['timestamp'],
            log_data['event_type'],
            log_data['username'],
            log_data['source_ip'],
            log_data['login_status']
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        # Ignore duplicate event IDs
        pass 
    finally:
        conn.close()

def get_recent_logs(limit=1000):
    """Fetch the most recent logs for the detection engine."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def create_alert(alert_type, severity, source_ip, evidence):
    """Create a new alert, preventing immediate duplicates for the same IP."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Duplicate prevention: Check if we already alerted on this IP for this type recently
    cursor.execute('''
        SELECT created_at FROM alerts 
        WHERE source_ip = ? AND alert_type = ? 
        ORDER BY id DESC LIMIT 1
    ''', (source_ip, alert_type))
    
    last_alert = cursor.fetchone()
    if last_alert:
        last_time = datetime.fromisoformat(last_alert['created_at'])
        # If the last alert for this IP was less than 10 minutes ago, ignore
        if datetime.now(timezone.utc) - last_time < timedelta(minutes=10):
            conn.close()
            return None

    created_at = datetime.now(timezone.utc).isoformat()
    cursor.execute('''
        INSERT INTO alerts (alert_type, severity, source_ip, evidence, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (alert_type, severity, source_ip, json.dumps(evidence), created_at))
    
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

# Let's run this file directly to initialize the database
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
