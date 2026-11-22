from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class EventQueue:
    """Durable event queue and Windows Security log checkpoint."""

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
            connection.execute("""
                CREATE TABLE IF NOT EXISTS agent_state (
                    state_key TEXT PRIMARY KEY,
                    state_value TEXT NOT NULL
                )
            """)

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @staticmethod
    def _encode(event: dict) -> tuple[str, str]:
        event_uid = event.get("event_uid")
        if not isinstance(event_uid, str) or not event_uid:
            raise ValueError("Queued events must have an event_uid.")
        encoded = json.dumps(event, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        return event_uid, encoded

    def add(self, event: dict) -> None:
        event_uid, encoded = self._encode(event)
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO pending_events (event_uid, payload) VALUES (?, ?)",
                (event_uid, encoded),
            )

    def add_batch_and_checkpoint(
        self,
        events: list[dict],
        record_id: int,
        channel: str = "security",
    ) -> None:
        """Persist discovered events and one Windows event-channel checkpoint atomically."""
        if channel not in {"security", "defender"}:
            raise ValueError("Unsupported Windows event channel.")
        if type(record_id) is not int or record_id < 0:
            raise ValueError("Invalid Windows event record checkpoint.")
        encoded_events = [self._encode(event) for event in events]
        state_key = f"{channel}_record_id"
        with self._connect() as connection:
            connection.executemany(
                "INSERT OR IGNORE INTO pending_events (event_uid, payload) VALUES (?, ?)",
                encoded_events,
            )
            current = connection.execute(
                "SELECT state_value FROM agent_state WHERE state_key = ?",
                (state_key,),
            ).fetchone()
            current_id = int(current[0]) if current else 0
            if record_id < current_id:
                raise ValueError("Windows event checkpoint cannot move backwards.")
            connection.execute(
                """INSERT INTO agent_state (state_key, state_value)
                   VALUES (?, ?)
                   ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value""",
                (state_key, str(record_id)),
            )

    def checkpoint(self, channel: str) -> int:
        if channel not in {"security", "defender"}:
            raise ValueError("Unsupported Windows event channel.")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state_value FROM agent_state WHERE state_key = ?",
                (f"{channel}_record_id",),
            ).fetchone()
        return int(row[0]) if row else 0

    def security_checkpoint(self) -> int:
        return self.checkpoint("security")

    def defender_checkpoint(self) -> int:
        return self.checkpoint("defender")

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
