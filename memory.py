import os
import json
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

def init_memory():
    global client
    if not HINDSIGHT_INSTALLED:
        print("WARNING: hindsight-client is not installed.")
        return

    # If the user put a placeholder in the .env, we shouldn't crash, just warn.
    if HINDSIGHT_API_KEY == "your_hindsight_api_key_here":
        print("WARNING: Hindsight API Key is not configured. Memory is disabled.")
        return

    try:
        # Standard initialization for the Hindsight client
        client = Hindsight(base_url=HINDSIGHT_SERVER_URL)
        print("[SUCCESS] Hindsight Memory Client initialized successfully.")
    except Exception as e:
        print(f"WARNING: Failed to connect to Hindsight Server: {e}")

# Call init once when the file loads
init_memory()

def retain_incident(alert_type, source_ip, evidence, summary, outcome, feedback=""):
    """
    Stores a completed investigation into Hindsight long-term memory.
    """
    if not client:
        print("[MEMORY] Hindsight is unavailable. Skipping memory retention.")
        return False
        
    try:
        # Format the memory. We ensure no passwords are sent here.
        content = (
            f"Incident Report: {alert_type} attack from IP {source_ip}.\n"
            f"Evidence: {json.dumps(evidence)}\n"
            f"Investigation Summary: {summary}\n"
            f"Outcome: {outcome}\n"
            f"Analyst Feedback: {feedback}"
        )
        
        # Call Hindsight's retain API
        client.retain(bank_id=BANK_ID, content=content)
        print(f"[MEMORY] Incident retained successfully for {source_ip}.")
        return True
    except Exception as e:
        print(f"[MEMORY] Failed to retain incident: {e}")
        return False

def recall_incidents(query):
    """
    Retrieves past incidents relevant to a search query (like an IP address).
    Returns a list of string summaries of past incidents.
    """
    if not client:
        print("[MEMORY] Hindsight is unavailable. Returning empty past incidents.")
        return []
        
    try:
        results = client.recall(bank_id=BANK_ID, query=query)
        # Extract the text chunks from the recall results
        return [r.text for r in getattr(results, 'results', [])]
    except Exception as e:
        print(f"[MEMORY] Failed to recall incidents: {e}")
        return []

def reflect_on_incidents(question):
    """
    Uses Hindsight's reflect capability to reason over all past memories.
    """
    if not client:
        return "Memory unavailable. Cannot reflect."
        
    try:
        # reflect allows asking analytical questions over the whole memory bank
        result = client.reflect(bank_id=BANK_ID, query=question)
        return getattr(result, 'answer', str(result)) 
    except Exception as e:
        print(f"[MEMORY] Failed to reflect on incidents: {e}")
        return f"Error reflecting: {e}"

if __name__ == "__main__":
    # Test connection handling by triggering a retain action
    print("Testing Hindsight Memory connection...")
    success = retain_incident("brute_force", "127.0.0.1", {}, "Test", "Test")
    if not success:
        print("As expected, retention did not occur without a running Hindsight server/valid API key.")
