"""Durable SQLite history for enrichment investigations."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_HISTORY_DB = Path.home() / ".local" / "share" / "iocforge-lab" / "history.db"


class HistoryStore:
    """Append-only lookup history plus a current indicator index.

    Migrations are tracked in SQLite so new schema versions can be applied
    safely to an analyst's existing local investigation database.
    """

    def __init__(self, path: Path | str = DEFAULT_HISTORY_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY)"
            )
            applied = {
                row[0]
                for row in self.conn.execute("SELECT version FROM schema_migrations")
            }
            if 1 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE indicators (
                        ioc TEXT PRIMARY KEY,
                        ioc_type TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        tags TEXT NOT NULL DEFAULT '[]',
                        status TEXT NOT NULL DEFAULT 'open',
                        analyst_notes TEXT NOT NULL DEFAULT ''
                    );
                    CREATE TABLE enrichments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        score REAL NOT NULL,
                        confidence TEXT NOT NULL,
                        looked_up_at TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        FOREIGN KEY(ioc) REFERENCES indicators(ioc)
                    );
                    CREATE INDEX idx_enrichments_ioc_time
                    ON enrichments(ioc, looked_up_at DESC);
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (1)")
            self.conn.commit()

    def record(self, result: Any, looked_up_at: str | None = None) -> int:
        """Persist an immutable enrichment snapshot and update indicator times."""
        timestamp = looked_up_at or datetime.now(timezone.utc).isoformat()
        payload = result.to_dict()
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO indicators(ioc, ioc_type, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ioc) DO UPDATE SET
                    ioc_type = excluded.ioc_type,
                    last_seen = excluded.last_seen
                """,
                (result.ioc, result.ioc_type.value, timestamp, timestamp),
            )
            cursor = self.conn.execute(
                """
                INSERT INTO enrichments(
                    ioc, ioc_type, verdict, score, confidence, looked_up_at, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.ioc,
                    result.ioc_type.value,
                    result.verdict,
                    result.score,
                    result.confidence,
                    timestamp,
                    json.dumps(payload, sort_keys=True),
                ),
            )
            self.conn.commit()
            if cursor.lastrowid is None:
                raise RuntimeError("failed to persist enrichment history")
            return int(cursor.lastrowid)

    def list_enrichments(
        self, ioc: str | None = None, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        query = "SELECT * FROM enrichments"
        params: list[Any] = []
        if ioc:
            query += " WHERE ioc = ?"
            params.append(ioc)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "ioc": row["ioc"],
                "ioc_type": row["ioc_type"],
                "verdict": row["verdict"],
                "score": row["score"],
                "confidence": row["confidence"],
                "looked_up_at": row["looked_up_at"],
                "result": json.loads(row["result_json"]),
            }
            for row in rows
        ]

    def indicator(self, ioc: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM indicators WHERE ioc = ?", (ioc,)
            ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.conn.close()
