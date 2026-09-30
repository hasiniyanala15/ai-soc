import json
from datetime import datetime, timezone
from database import get_connection
from memory import recall_incidents, retain_incident
from investigator import investigate_alert

def process_alert(alert_id):
    """
    The main AI Agent workflow. Orchestrates memory, detection, and investigation.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Receive an alert: Fetch details from DB
    cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
    alert_row = cursor.fetchone()
    
    if not alert_row:
        conn.close()
        return {"error": f"Alert ID {alert_id} not found."}
        
    alert_data = dict(alert_row)
    evidence = json.loads(alert_data['evidence'])
    source_ip = alert_data['source_ip']
    
    # Prevent unnecessary repeated API calls if we already investigated this alert
    cursor.execute('SELECT * FROM reports WHERE alert_id = ?', (alert_id,))
    existing_report = cursor.fetchone()
    if existing_report:
        conn.close()
        return dict(existing_report)

    # 2 & 3. Recall relevant past incidents from Hindsight memory
    print(f"[AGENT] Recalling past incidents for IP {source_ip}...")
    past_incidents = recall_incidents(query=f"IP {source_ip}")
    
    # Check for analyst feedback on this alert (if they triggered reinvestigation)
    cursor.execute('SELECT analyst_notes FROM feedback WHERE alert_id = ?', (alert_id,))
    feedback_row = cursor.fetchone()
    feedback = feedback_row['analyst_notes'] if feedback_row else ""

    # 4 & 5. Investigate using the LLM AI
    print(f"[AGENT] Investigating alert {alert_id} with AI...")
    report = investigate_alert(
        alert_data=alert_data,
        evidence=evidence,
        past_incidents=past_incidents,
        feedback=feedback
    )
    
    # Handle LLM failure gracefully
    if "error" in report:
        conn.close()
        return report
        
    # 6. Store the investigation report in SQLite
    print(f"[AGENT] Saving investigation report to database...")
    created_at = datetime.now(timezone.utc).isoformat()
    cursor.execute('''
        INSERT INTO reports (alert_id, summary, attack_type, confidence, recommended_action, full_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_id,
        report.get('alert_summary', 'No summary provided.'),
        report.get('attack_type', 'unknown'),
        report.get('confidence_level', 'Unknown'),
        json.dumps(report.get('recommended_investigation_steps', [])),
        json.dumps(report),
        created_at
    ))
    conn.commit()
    
    # 7. Retain the completed incident in Hindsight to learn for the future!
    print(f"[AGENT] Retaining knowledge in Hindsight Memory...")
    retain_incident(
        alert_type=alert_data['alert_type'],
        source_ip=source_ip,
        evidence=evidence,
        summary=report.get('alert_summary', ''),
        outcome=report.get('recommended_response', ''),
        feedback=feedback
    )
    
    conn.close()
    
    # 8. Return the report
    return report

if __name__ == "__main__":
    # Test block: Try to investigate Alert ID 1
    print("Testing the full agent workflow on Alert 1...")
    result = process_alert(1)
    print("Agent Result:")
    print(json.dumps(result, indent=2))
