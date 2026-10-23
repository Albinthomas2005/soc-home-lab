
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "soc_alerts.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule TEXT NOT NULL,
                source_ip TEXT,
                status TEXT NOT NULL DEFAULT 'New'
            )
        """)


def add_alert(timestamp, severity, rule, source_ip, status="New"):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO alerts
                (timestamp, severity, rule, source_ip, status)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, severity, rule, source_ip, status))


def get_alerts():
    with get_connection() as connection:
        return connection.execute("""
            SELECT * FROM alerts ORDER BY id DESC
        """).fetchall()


if __name__ == "__main__":
    init_db()
    print(f"Database created: {DB_PATH}")


def get_raw_alerts(limit=100):
    """Return recent raw Wazuh alerts without modifying their stored JSON."""
    with get_connection() as connection:
        return connection.execute("""
            SELECT wazuh_id, timestamp, raw_json
            FROM wazuh_raw_alerts
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()


def get_raw_alert(wazuh_id):
    """Retrieve one complete original Wazuh alert by its ID."""
    with get_connection() as connection:
        return connection.execute("""
            SELECT wazuh_id, timestamp, raw_json
            FROM wazuh_raw_alerts
            WHERE wazuh_id = ?
        """, (wazuh_id,)).fetchone()
