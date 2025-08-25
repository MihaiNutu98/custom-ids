import sqlite3
from datetime import datetime

DB_PATH = "ids_alerts.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            proto TEXT,
            category TEXT,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_alert(src_ip, dst_ip, proto, category, description):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO alerts (ts, src_ip, dst_ip, proto, category, description) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, src_ip, dst_ip, proto, category, description)
    )
    conn.commit()
    conn.close()

