import os
import json
import sqlite3
from dotenv import load_dotenv

try:
    from hindsight_client import Hindsight
    HINDSIGHT_INSTALLED = True
except ImportError:
    HINDSIGHT_INSTALLED = False

load_dotenv()

# Configuration
HINDSIGHT_API_KEY = os.getenv("HINDSIGHT_API_KEY", "")
HINDSIGHT_SERVER_URL = os.getenv("HINDSIGHT_SERVER_URL", "http://localhost:8888") 
BANK_ID = "ai-soc-agent-bank"

# Initialize client. We wrap in try-except for graceful failure.
client = None
fallback_db = "data/memory_fallback.db"

def init_fallback_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(fallback_db)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS memories 
        USING fts5(content)
    """)
    conn.commit()
    conn.close()

def init_memory():
    global client
    init_fallback_db()
    
    if not HINDSIGHT_INSTALLED:
        print("WARNING: hindsight-client is not installed. Using local SQLite fallback.")
        return

    # If the user put a placeholder in the .env, we shouldn't crash, just warn.
    if HINDSIGHT_API_KEY == "your_hindsight_api_key_here":
        print("WARNING: Hindsight API Key is not configured. Using local SQLite fallback.")
        return

    try:
        # Standard initialization for the Hindsight client
        client = Hindsight(base_url=HINDSIGHT_SERVER_URL)
        print("[SUCCESS] Hindsight Memory Client initialized successfully.")
    except Exception as e:
        print(f"WARNING: Failed to connect to Hindsight Server: {e}")
        client = None

# Call init once when the file loads
init_memory()

def retain_incident(alert_type, source_ip, evidence, summary, outcome, feedback=""):
    """
    Stores a completed investigation into Hindsight long-term memory or local fallback.
    """
    content = (
        f"Incident Report: {alert_type} attack from IP {source_ip}.\n"
        f"Evidence: {json.dumps(evidence)}\n"
        f"Investigation Summary: {summary}\n"
        f"Outcome: {outcome}\n"
        f"Analyst Feedback: {feedback}"
    )

    if client:
        try:
            client.retain(bank_id=BANK_ID, content=content)
            print(f"[MEMORY] Incident retained successfully for {source_ip}.")
            return True
        except Exception as e:
            print(f"[MEMORY] Hindsight failed, falling back to local DB: {e}")
            
    # Fallback to local DB
    try:
        conn = sqlite3.connect(fallback_db)
        conn.execute("INSERT INTO memories (content) VALUES (?)", (content,))
        conn.commit()
        conn.close()
        print(f"[MEMORY-FALLBACK] Incident retained locally for {source_ip}.")
        return True
    except Exception as e:
        print(f"[MEMORY-FALLBACK] Failed to retain incident: {e}")
        return False

def recall_incidents(query):
    """
    Retrieves past incidents relevant to a search query (like an IP address).
    Returns a list of string summaries of past incidents.
    """
    if client:
        try:
            results = client.recall(bank_id=BANK_ID, query=query)
            return [r.text for r in getattr(results, 'results', [])]
        except Exception as e:
            print(f"[MEMORY] Hindsight failed, falling back to local DB: {e}")
            
    # Fallback to local DB
    try:
        conn = sqlite3.connect(fallback_db)
        # We replace spaces with AND for FTS search
        fts_query = " AND ".join(f'"{term}"' for term in str(query).split())
        cursor = conn.execute("SELECT content FROM memories WHERE memories MATCH ? LIMIT 5", (fts_query,))
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        # If no results on FTS, try a LIKE fallback
        if not results:
            conn = sqlite3.connect(fallback_db)
            like_query = f"%{query}%"
            cursor = conn.execute("SELECT content FROM memories WHERE content LIKE ? LIMIT 5", (like_query,))
            results = [row[0] for row in cursor.fetchall()]
            conn.close()
            
        return results
    except Exception as e:
        print(f"[MEMORY-FALLBACK] Failed to recall incidents: {e}")
        return []

def reflect_on_incidents(question):
    """
    Uses Hindsight's reflect capability to reason over all past memories.
    """
    if client:
        try:
            result = client.reflect(bank_id=BANK_ID, query=question)
            return getattr(result, 'answer', str(result)) 
        except Exception as e:
            print(f"[MEMORY] Hindsight failed to reflect: {e}")
            
    return "Memory unavailable or using local fallback (Reflection not supported offline)."

if __name__ == "__main__":
    # Test connection handling by triggering a retain action
    print("Testing Hindsight Memory connection...")
    success = retain_incident("brute_force", "127.0.0.1", {}, "Test", "Test")
    if not success:
        print("As expected, retention did not occur without a running Hindsight server/valid API key.")

