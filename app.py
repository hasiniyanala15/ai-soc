from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import json
from datetime import datetime, timezone
from database import get_connection, init_db, create_alert
from log_generator import generate_logs
from detector import run_detection
from agent import process_alert
from dotenv import load_dotenv, set_key, dotenv_values

load_dotenv()
ENV_FILE = '.env'

app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing for the frontend

# Initialize DB on startup
init_db()

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "online",
        "version": "1.0",
        "message": "AI SOC Agent Backend is running."
    })

@app.route('/health', methods=['GET'])
def health():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/logs/generate', methods=['POST'])
def generate_sample_logs():
    data = request.get_json(silent=True) or {}
    num_normal = data.get('num_normal', 20)
    brute_force = data.get('generate_brute_force', True)
    
    logs = generate_logs(num_normal=num_normal, generate_brute_force=brute_force)
    return jsonify({"message": f"Generated {len(logs)} logs successfully."}), 201

@app.route('/logs', methods=['GET'])
def get_logs():
    limit = request.args.get('limit', 100)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"logs": logs})

@app.route('/alerts', methods=['GET'])
def get_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY created_at DESC')
    alerts = [dict(row) for row in cursor.fetchall()]
    # Safely load JSON evidence
    for alert in alerts:
        alert['evidence'] = json.loads(alert['evidence'])
    conn.close()
    return jsonify({"alerts": alerts})

@app.route('/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
    alert = cursor.fetchone()
    conn.close()
    
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
        
    alert_dict = dict(alert)
    alert_dict['evidence'] = json.loads(alert_dict['evidence'])
    return jsonify({"alert": alert_dict})

@app.route('/alerts/detect', methods=['POST'])
def detect_alerts():
    alerts_created = run_detection()
    return jsonify({
        "message": "Detection engine executed.",
        "new_alerts": alerts_created
    }), 200

@app.route('/train', methods=['POST'])
def train():
    try:
        from train_model import train_isolation_forest
        success = train_isolation_forest()
        if success:
            return jsonify({"message": "ML Model trained successfully using Isolation Forest."})
        else:
            return jsonify({"error": "Failed to train model. Generate more logs first."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/alerts/<int:alert_id>/investigate', methods=['POST'])
def investigate_endpoint(alert_id):
    result = process_alert(alert_id)
    if "error" in result:
        # Simple heuristic to determine if it's a 404 vs 500
        status_code = 404 if "not found" in result["error"].lower() else 500
        return jsonify(result), status_code
        
    return jsonify({"message": "Investigation complete", "report": result}), 200

@app.route('/alerts/<int:alert_id>/report', methods=['GET'])
def get_report(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports WHERE alert_id = ?', (alert_id,))
    report = cursor.fetchone()
    conn.close()
    
    if not report:
        return jsonify({"error": "Report not found"}), 404
        
    report_dict = dict(report)
    report_dict['recommended_action'] = json.loads(report_dict['recommended_action'])
    return jsonify({"report": report_dict})

@app.route('/alerts/<int:alert_id>/feedback', methods=['POST'])
def save_feedback(alert_id):
    data = request.json
    if not data or 'analyst_notes' not in data:
        return jsonify({"error": "Missing analyst_notes in JSON payload"}), 400
        
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if alert exists
    cursor.execute('SELECT id FROM alerts WHERE id = ?', (alert_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Alert not found"}), 404
        
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        cursor.execute('''
            INSERT INTO feedback (alert_id, analyst_notes, was_helpful, created_at)
            VALUES (?, ?, ?, ?)
        ''', (alert_id, data['analyst_notes'], data.get('was_helpful', True), created_at))
        conn.commit()
    except Exception as e: # Catch duplicate UNIQUE constraint
        cursor.execute('''
            UPDATE feedback SET analyst_notes = ?, was_helpful = ? WHERE alert_id = ?
        ''', (data['analyst_notes'], data.get('was_helpful', True), alert_id))
        conn.commit()
        
    conn.close()
    return jsonify({"message": "Feedback saved successfully"}), 201

@app.route('/ml/predict', methods=['POST'])
def ml_predict():
    """
    Step 12: Flask API Integration
    Receives a single event and returns the ML prediction.
    """
    event = request.json
    if not event:
        return jsonify({"error": "No event data provided", "status": "failed"}), 400
        
    try:
        from ml.threat_predictor import predict_threat
        result = predict_threat(event)
        
        if result.get("status") == "failed":
            return jsonify(result), 400
            
        return jsonify(result), 200
    except ImportError:
        return jsonify({"error": "ML module not found", "status": "failed"}), 500

@app.route('/ml/sniff', methods=['GET'])
def ml_sniff():
    """
    Captures a real live packet, runs it through the ML model, and returns both.
    """
    try:
        from ml.live_sniffer import capture_live_packet
        from ml.threat_predictor import predict_threat
        
        sniff_result = capture_live_packet()
        if "error" in sniff_result:
            return jsonify(sniff_result), 400
            
        packet_features = sniff_result["packet"]
        prediction = predict_threat(packet_features)
        
        # Check if threat is detected and create alert
        attack_type = prediction.get("predicted_class", "Benign")
        
        severity = "LOW"
        action = "No action required. Normal traffic."
        
        if attack_type == "PortScan":
            severity = "MEDIUM"
            action = "Rate-limit IP and monitor for further suspicious requests."
        elif attack_type in ["Bot", "DDoS"]:
            severity = "HIGH"
            action = "Immediately block Source IP and activate DDoS mitigation protocols."
        elif attack_type == "Brute Force":
            severity = "HIGH"
            action = "Block IP at Firewall and investigate payload."
            
        evidence = {
            "reason": f"Live Network Sniffer analyzed packet: {attack_type}.",
            "packet_features": packet_features,
            "confidence": prediction.get("confidence_score"),
            "Description": f"Live Sniffer analyzed {attack_type} packet.",
            "Recommended Action": action
        }
        
        src_ip = packet_features.get("Source IP", "Unknown")
        alert_id = create_alert(
            alert_type=attack_type,
            severity=severity,
            source_ip=src_ip,
            evidence=evidence
        )
        prediction["alert_created"] = (alert_id is not None)
        prediction["alert_id"] = alert_id
        
        # Merge the raw_summary into the response
        prediction["raw_summary"] = sniff_result.get("raw_summary", "")
        prediction["packet"] = packet_features
        
        return jsonify(prediction), 200
    except Exception as e:
        return jsonify({"error": f"Sniffing error: {str(e)}", "status": "failed"}), 500

@app.route('/ml/simulate', methods=['POST'])
def ml_simulate():
    """
    Injects a hardcoded malicious packet into the ML engine for testing purposes.
    Generates a random IP to bypass the 10-minute duplicate alert anti-spam filter.
    """
    try:
        from ml.threat_predictor import predict_threat
        import random
        
        simulated_ip = f"198.51.100.{random.randint(1, 254)}"
        
        # Hardcoded PortScan signature
        packet_features = {
            "Source IP": simulated_ip,
            "Flow Duration": 5, 
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 0,
            "Destination Port": 445,
            "Protocol": 6,
            "Flow Bytes/s": 0,
            "Failed Logins": 0
        }
        
        prediction = predict_threat(packet_features)
        
        attack_type = prediction.get("predicted_class", "Benign")
        
        severity = "LOW"
        action = "No action required. Normal traffic."
        
        if attack_type == "PortScan":
            severity = "MEDIUM"
            action = "Rate-limit IP and monitor for further suspicious requests."
        elif attack_type in ["Bot", "DDoS"]:
            severity = "HIGH"
            action = "Immediately block Source IP and activate DDoS mitigation protocols."
        elif attack_type == "Brute Force":
            severity = "HIGH"
            action = "Block IP at Firewall and investigate payload."
            
        evidence = {
            "reason": f"Simulated {attack_type} packet anomaly.",
            "packet_features": packet_features,
            "confidence": prediction.get("confidence_score"),
            "Description": f"Simulated {attack_type} attack.",
            "Recommended Action": action
        }
        
        alert_id = create_alert(
            alert_type=attack_type,
            severity=severity,
            source_ip=simulated_ip,
            evidence=evidence
        )
        # Only say alert created if it wasn't blocked by anti-spam
        prediction["alert_created"] = (alert_id is not None)
        prediction["alert_id"] = alert_id
            
        prediction["raw_summary"] = "Simulated Attack Packet Injected"
        prediction["packet"] = packet_features
        
        return jsonify(prediction), 200
    except Exception as e:
        return jsonify({"error": f"Simulate error: {str(e)}", "status": "failed"}), 500

@app.route('/ml/status', methods=['GET'])
def ml_status():
    """Returns the loaded status of the ML model."""
    try:
        import os
        import json
        if os.path.exists("models/metadata.json"):
            with open("models/metadata.json", "r") as f:
                meta = json.load(f)
            return jsonify({
                "status": "loaded",
                "model_type": meta.get("model_type"),
                "version": meta.get("version"),
                "supported_classes": meta.get("classes")
            }), 200
        else:
            return jsonify({"status": "unconfigured", "message": "Model not trained yet."}), 200
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500

@app.route('/memory/status', methods=['GET'])
def memory_status():
    api_key = os.getenv("HINDSIGHT_API_KEY", "")
    url = os.getenv("HINDSIGHT_SERVER_URL", "None")
    
    is_configured = bool(api_key and api_key != "your_hindsight_api_key_here")
    
    return jsonify({
        "status": "Configured" if is_configured else "Unconfigured",
        "hindsight_server_url": url,
        "message": "Memory is active" if is_configured else "Memory is disabled due to missing API Key. Fallback active."
    })

def mask_key(key):
    if not key or len(key) < 8:
        return key
    return key[:4] + "*" * 20 + key[-4:]

@app.route('/settings', methods=['GET'])
def get_settings():
    """Returns the current settings from the .env file with masked API keys"""
    env_vars = dotenv_values(ENV_FILE)
    
    return jsonify({
        "LLM_API_KEY": mask_key(env_vars.get("LLM_API_KEY", "")),
        "LLM_API_URL": env_vars.get("LLM_API_URL", ""),
        "LLM_MODEL": env_vars.get("LLM_MODEL", ""),
        "HINDSIGHT_API_KEY": mask_key(env_vars.get("HINDSIGHT_API_KEY", "")),
        "SNIFFER_TIMEOUT": env_vars.get("SNIFFER_TIMEOUT", "3")
    })

@app.route('/settings', methods=['POST'])
def update_settings():
    """Updates the .env file with new settings, ignoring masked keys"""
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
        
    allowed_keys = ["LLM_API_KEY", "LLM_API_URL", "LLM_MODEL", "HINDSIGHT_API_KEY", "SNIFFER_TIMEOUT"]
    
    try:
        for key, value in data.items():
            if key in allowed_keys:
                str_val = str(value)
                # If it's a masked key (contains ***), the user didn't change it, so don't overwrite the real key
                if key in ["LLM_API_KEY", "HINDSIGHT_API_KEY"] and "***" in str_val:
                    continue
                    
                set_key(ENV_FILE, key, str_val)
                os.environ[key] = str_val # Update current process memory
                
        # Reload dotenv fully
        load_dotenv(override=True)
        return jsonify({"message": "Settings updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to save settings: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
