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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE,
                    description TEXT,
                    secret TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            
            # Initialize default settings if not present
            defaults = {
                "min_domain_age_days": "30",
                "max_entropy_threshold": "4.0",
                "jurisdiction_jump_limit": "3",
                "enable_vision_ai": "1"
            }
            for k, v in defaults.items():
                conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
                
            conn.commit()
        finally:
            conn.close()

    def _get_hash(self, url):
        return hashlib.sha256(url.encode()).hexdigest()

    def get(self, url, max_age_days=1):
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
                "SELECT url_hash, url, report_json, timestamp FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [{"hash": row[0], "url": row[1], "report": json.loads(row[2]), "timestamp": row[3]} for row in rows]
        finally:
            conn.close()
        return []

    def get_stats(self):
        """Aggregate stats for analytics nodes."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM scans")
            total = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT report_json FROM scans")
            reports = [json.loads(r[0]) for r in cursor.fetchall()]
            
            malicious = sum(1 for r in reports if r.get("is_malicious"))
            
            # Entropy distribution
            entropies = [r.get("entropy", 0) for r in reports]
            
            # Geo distribution
            geo_counts = {}
            for r in reports:
                country = r.get("geo", {}).get("country", "Unknown")
                geo_counts[country] = geo_counts.get(country, 0) + 1
                
            return {
                "total_scans": total,
                "malicious_scans": malicious,
                "secure_scans": total - malicious,
                "avg_entropy": sum(entropies) / len(entropies) if entropies else 0,
                "geo_distribution": [{"name": k, "value": v} for k, v in geo_counts.items()],
                "risk_ratio": (malicious / total * 100) if total > 0 else 0
            }
        finally:
            conn.close()

    def set_setting(self, key, value):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()
        finally:
            conn.close()

    def get_setting(self, key, default=None):
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else default
        finally:
            conn.close()
        return default

    def get_all_settings(self):
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("SELECT key, value FROM settings")
            return {row[0]: row[1] for row in cursor.fetchall()}
        finally:
            conn.close()
        return {}

    def register_webhook(self, url, description, secret=None):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO webhooks (url, description, secret) VALUES (?, ?, ?)",
                (url, description, secret)
            )
            conn.commit()
        finally:
            conn.close()

    def get_active_webhooks(self):
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("SELECT url, secret FROM webhooks WHERE is_active = 1")
            return [{"url": row[0], "secret": row[1]} for row in cursor.fetchall()]
        finally:
            conn.close()
        return []
