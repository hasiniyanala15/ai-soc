import sqlite3

def update_db():
    conn = sqlite3.connect('data/soc_agent.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET severity = 'HIGH' WHERE severity = 'CRITICAL'")
    conn.commit()
    print(f"Updated {cursor.rowcount} alerts from CRITICAL to HIGH.")
    conn.close()

if __name__ == "__main__":
    update_db()
