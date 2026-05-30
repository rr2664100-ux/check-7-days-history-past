import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from config.constants import DB_FILE
from config.settings import DEFAULT_DATABASE_SCHEMA, SETTINGS
from utils.helpers import ensure_directory, get_timestamp
from utils.logger import logger


class LocalDatabase:
    def __init__(self) -> None:
        self.db_path = Path(DB_FILE)
        ensure_directory(self.db_path.parent)
        self.connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.cursor = self.connection.cursor()
        self._setup_database()
        self.cleanup_old_entries(SETTINGS.get("retention_days", 7))

    def _setup_database(self) -> None:
        logger.debug("Initializing local SQLite database.")
        for table_name, columns in DEFAULT_DATABASE_SCHEMA.items():
            columns_sql = ", ".join([f"{name} {definition}" for name, definition in columns])
            self.cursor.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({columns_sql})")
        self.connection.commit()

    def insert_event(self, source: str, category: str, message: str, level: str) -> None:
        self.cursor.execute(
            "INSERT INTO events (timestamp, source, category, message, level) VALUES (?, ?, ?, ?, ?)",
            (get_timestamp(), source, category, message, level),
        )
        self.connection.commit()

    def insert_process_event(self, process_name: str, pid: int, path: str, cpu_percent: float, memory_mb: float, status: str) -> None:
        self.cursor.execute(
            "INSERT INTO process_events (timestamp, process_name, pid, path, cpu_percent, memory_mb, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (get_timestamp(), process_name, pid, path, cpu_percent, memory_mb, status),
        )
        self.connection.commit()

    def insert_alert(self, alert_text: str, source: str, severity: str, risk_score: int) -> None:
        self.cursor.execute(
            "INSERT INTO alerts (timestamp, alert_text, source, severity, risk_score) VALUES (?, ?, ?, ?, ?)",
            (get_timestamp(), alert_text, source, severity, risk_score),
        )
        self.connection.commit()

    def insert_recommendation(self, recommendation: str, context: str) -> None:
        self.cursor.execute(
            "INSERT INTO recommendations (timestamp, recommendation, context) VALUES (?, ?, ?)",
            (get_timestamp(), recommendation, context),
        )
        self.connection.commit()

    def insert_activity(self, event_type: str, app_name: str, message: str, severity: str = "Safe") -> None:
        self.cursor.execute(
            "INSERT INTO activities (timestamp, event_type, app_name, message, severity) VALUES (?, ?, ?, ?, ?)",
            (get_timestamp(), event_type, app_name, message, severity),
        )
        self.connection.commit()

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        self.cursor.execute("SELECT timestamp, alert_text, source, severity, risk_score FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        rows = self.cursor.fetchall()
        return [
            {
                "timestamp": row[0],
                "alert_text": row[1],
                "source": row[2],
                "severity": row[3],
                "risk_score": row[4],
            }
            for row in rows
        ]

    def get_recent_activities(self, limit: int = 20) -> List[Dict[str, Any]]:
        self.cursor.execute(
            "SELECT timestamp, event_type, app_name, message, severity FROM activities ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = self.cursor.fetchall()
        return [
            {
                "timestamp": row[0],
                "event_type": row[1],
                "app_name": row[2],
                "message": row[3],
                "severity": row[4],
            }
            for row in rows
        ]

    def cleanup_old_entries(self, days: int = 7) -> None:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        tables = ["events", "process_events", "alerts", "recommendations", "activities"]
        for table in tables:
            try:
                self.cursor.execute(
                    f"DELETE FROM {table} WHERE timestamp < ?",
                    (cutoff,),
                )
            except Exception as exc:
                logger.debug("Failed to clean up table %s: %s", table, exc)
        self.connection.commit()

    def search_logs(
        self,
        keyword: str = "",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT timestamp, alert_text, source, severity, risk_score FROM alerts WHERE 1=1"
        params: List[Any] = []

        if keyword:
            query += " AND (alert_text LIKE ? OR source LIKE ? OR severity LIKE ?)"
            like_value = f"%{keyword}%"
            params.extend([like_value, like_value, like_value])

        if severity:
            query += " AND severity LIKE ?"
            params.append(f"%{severity}%")

        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)

        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        return [
            {
                "timestamp": row[0],
                "alert_text": row[1],
                "source": row[2],
                "severity": row[3],
                "risk_score": row[4],
            }
            for row in rows
        ]

    def get_7day_analysis(self) -> Dict[str, int]:
        cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        summary = {
            "failed_logins": 0,
            "usb_insertions": 0,
            "suspicious_powershell": 0,
            "unknown_executables": 0,
            "remote_connections": 0,
            "high_memory": 0,
            "critical_alerts": 0,
        }

        try:
            self.cursor.execute(
                "SELECT alert_text, severity FROM alerts WHERE timestamp >= ?",
                (cutoff,),
            )
            rows = self.cursor.fetchall()
            for alert_text, severity in rows:
                normalized = (alert_text or "").lower()
                if "failed login" in normalized or "failed" in normalized:
                    summary["failed_logins"] += 1
                if "usb" in normalized:
                    summary["usb_insertions"] += 1
                if "powershell" in normalized:
                    summary["suspicious_powershell"] += 1
                if "unknown" in normalized or "unspecified" in normalized:
                    summary["unknown_executables"] += 1
                if "remote" in normalized or "outbound" in normalized:
                    summary["remote_connections"] += 1
                if "high memory" in normalized or "cpu usage" in normalized:
                    summary["high_memory"] += 1
                if severity and severity.lower() == "critical":
                    summary["critical_alerts"] += 1
        except Exception as exc:
            logger.debug("7-day summary query failed: %s", exc)

        return summary

    def close(self) -> None:
        self.connection.close()
