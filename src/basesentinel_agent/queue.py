from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class EventQueue:
    """Small durable queue; event_uid is retained across delivery retries."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS pending_events (
                    event_uid TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def add(self, event: dict) -> None:
        event_uid = event.get("event_uid")
        if not isinstance(event_uid, str) or not event_uid:
            raise ValueError("Queued events must have an event_uid.")
        encoded = json.dumps(event, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO pending_events (event_uid, payload) VALUES (?, ?)",
                (event_uid, encoded),
            )

    def pending(self, limit: int = 50) -> list[dict]:
        if not 1 <= limit <= 500:
            raise ValueError("Queue batch size must be between 1 and 500.")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM pending_events ORDER BY queued_at, event_uid LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def acknowledge(self, event_uid: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM pending_events WHERE event_uid = ?", (event_uid,))

    def __len__(self) -> int:
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM pending_events").fetchone()[0]
