import sqlite3
import json
import hashlib
import os
from datetime import datetime, timedelta

DB_PATH = os.path.expanduser("~/.malicious_link_detector.db")

class ScanCache:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    url_hash TEXT PRIMARY KEY,
                    url TEXT,
                    report_json TEXT,
                    timestamp DATETIME
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_hash(self, url):
        return hashlib.sha256(url.encode()).hexdigest()

    def get(self, url, max_age_days=7):
        url_hash = self._get_hash(url)
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT report_json, timestamp FROM scans WHERE url_hash = ?",
                (url_hash,)
            )
            row = cursor.fetchone()
            if row:
                report_json, timestamp_str = row
                timestamp = datetime.fromisoformat(timestamp_str)
                if datetime.now() - timestamp < timedelta(days=max_age_days):
                    return json.loads(report_json)
        finally:
            conn.close()
        return None

    def set(self, url, report):
        url_hash = self._get_hash(url)
        report_json = json.dumps(report)
        timestamp = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO scans (url_hash, url, report_json, timestamp) VALUES (?, ?, ?, ?)",
                (url_hash, url, report_json, timestamp)
            )
            conn.commit()
        finally:
            conn.close()

    def get_history(self, limit=20):
        """Retrieve recent scan results."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT url, report_json, timestamp FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [{"url": row[0], "report": json.loads(row[1]), "timestamp": row[2]} for row in rows]
        finally:
            conn.close()
        return []
