from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock
from time import time

from core.models import Decision, RequestContext


class ForensicsLogger:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    route TEXT NOT NULL,
                    payload_snippet TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    reasons_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip)")
            conn.commit()

    def record(self, context: RequestContext, decision: Decision) -> None:
        if decision.risk_score == 0 and decision.action.value == "allow":
            return
        findings = [finding.__dict__ for finding in decision.findings]
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO security_events (
                    timestamp, ip, method, route, payload_snippet, attack_type,
                    risk_score, action, findings_json, reasons_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    context.timestamp,
                    context.ip,
                    context.method,
                    context.route,
                    context.payload_snippet,
                    decision.attack_types,
                    decision.risk_score,
                    decision.action.value,
                    json.dumps(findings),
                    json.dumps(decision.reasons),
                ),
            )
            conn.commit()

    def query_events(self, limit: int = 100, ip: str | None = None) -> list[dict[str, object]]:
        limit = max(1, min(limit, 500))
        sql = "SELECT * FROM security_events"
        params: list[object] = []
        if ip:
            sql += " WHERE ip = ?"
            params.append(ip)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self.lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def stats(self) -> dict[str, object]:
        since = time() - 3600
        with self.lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            recent = conn.execute("SELECT COUNT(*) FROM security_events WHERE timestamp >= ?", (since,)).fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM security_events WHERE action = 'block'").fetchone()[0]
            top = conn.execute(
                """
                SELECT attack_type, COUNT(*) AS count
                FROM security_events
                GROUP BY attack_type
                ORDER BY count DESC
                LIMIT 5
                """
            ).fetchall()
        return {
            "total_events": total,
            "events_last_hour": recent,
            "blocked_events": blocked,
            "top_attack_types": [dict(row) for row in top],
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, object]:
        item = dict(row)
        item["findings"] = json.loads(str(item.pop("findings_json")))
        item["reasons"] = json.loads(str(item.pop("reasons_json")))
        return item
