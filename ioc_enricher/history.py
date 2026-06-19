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
            if 2 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE indicator_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        data_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(ioc) REFERENCES indicators(ioc)
                    );
                    CREATE INDEX idx_indicator_events_ioc_time
                    ON indicator_events(ioc, created_at DESC);
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (2)")
            if 3 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE investigations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'open',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE investigation_indicators (
                        investigation_id INTEGER NOT NULL,
                        ioc TEXT NOT NULL,
                        added_at TEXT NOT NULL,
                        PRIMARY KEY(investigation_id, ioc),
                        FOREIGN KEY(investigation_id) REFERENCES investigations(id)
                    );
                    CREATE TABLE investigation_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        investigation_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        data_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(investigation_id) REFERENCES investigations(id)
                    );
                    CREATE INDEX idx_investigation_events_time
                    ON investigation_events(investigation_id, created_at DESC);
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (3)")
            if 4 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE indicator_relationships (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_ioc TEXT NOT NULL,
                        target_ioc TEXT NOT NULL,
                        relationship_type TEXT NOT NULL,
                        confidence REAL NOT NULL DEFAULT 1.0,
                        evidence_source TEXT NOT NULL DEFAULT 'analyst',
                        created_at TEXT NOT NULL,
                        UNIQUE(source_ioc, target_ioc, relationship_type, evidence_source)
                    );
                    CREATE INDEX idx_relationships_source ON indicator_relationships(source_ioc);
                    CREATE INDEX idx_relationships_target ON indicator_relationships(target_ioc);
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (4)")
            if 5 not in applied:
                self.conn.executescript(
                    """
                    ALTER TABLE indicators ADD COLUMN verdict_override TEXT;
                    ALTER TABLE indicators ADD COLUMN override_reason TEXT;
                    ALTER TABLE indicators ADD COLUMN override_at TEXT;
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (5)")
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

    def dashboard_summary(self, recent_limit: int = 10) -> dict[str, Any]:
        """Return compact persisted metrics for an analyst dashboard."""
        with self._lock:
            verdict_rows = self.conn.execute(
                "SELECT verdict, COUNT(*) AS count FROM enrichments GROUP BY verdict"
            ).fetchall()
            investigation_rows = self.conn.execute(
                "SELECT status, COUNT(*) AS count FROM investigations GROUP BY status"
            ).fetchall()
        return {
            "verdict_counts": {row["verdict"]: row["count"] for row in verdict_rows},
            "investigation_counts": {row["status"]: row["count"] for row in investigation_rows},
            "recent_enrichments": self.list_enrichments(limit=recent_limit),
        }

    def indicator(self, ioc: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM indicators WHERE ioc = ?", (ioc,)
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["tags"] = json.loads(result["tags"])
        return result

    def update_indicator(
        self,
        ioc: str,
        tags: list[str] | None = None,
        status: str | None = None,
        analyst_notes: str | None = None,
    ) -> dict[str, Any] | None:
        """Update analyst-managed fields and preserve a timestamped audit event."""
        if status and status not in {"open", "triaged", "benign", "malicious", "closed"}:
            raise ValueError("invalid indicator status")
        fields: dict[str, Any] = {}
        if tags is not None:
            fields["tags"] = json.dumps(sorted({tag.strip().lower() for tag in tags if tag.strip()}))
        if status is not None:
            fields["status"] = status
        if analyst_notes is not None:
            fields["analyst_notes"] = analyst_notes
        if not fields:
            return self.indicator(ioc)

        with self._lock:
            current = self.conn.execute(
                "SELECT ioc FROM indicators WHERE ioc = ?", (ioc,)
            ).fetchone()
            if not current:
                return None
            assignments = ", ".join(f"{field} = ?" for field in fields)
            self.conn.execute(
                f"UPDATE indicators SET {assignments} WHERE ioc = ?",
                [*fields.values(), ioc],
            )
            self.conn.execute(
                "INSERT INTO indicator_events(ioc, event_type, data_json, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    ioc,
                    "indicator_updated",
                    json.dumps(fields, sort_keys=True),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self.conn.commit()
        return self.indicator(ioc)

    def indicator_events(self, ioc: str, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, event_type, data_json, created_at FROM indicator_events "
                "WHERE ioc = ? ORDER BY id DESC LIMIT ?",
                (ioc, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "data": json.loads(row["data_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def set_verdict_override(
        self, ioc: str, verdict: str, reason: str
    ) -> dict[str, Any] | None:
        """Set an auditable analyst verdict distinct from source-derived scoring."""
        if verdict not in {"clean", "low", "suspicious", "malicious"}:
            raise ValueError("invalid override verdict")
        reason = reason.strip()
        if not reason:
            raise ValueError("override reason is required")
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            exists = self.conn.execute(
                "SELECT ioc FROM indicators WHERE ioc = ?", (ioc,)
            ).fetchone()
            if not exists:
                return None
            data = {"verdict_override": verdict, "override_reason": reason, "override_at": timestamp}
            self.conn.execute(
                "UPDATE indicators SET verdict_override = ?, override_reason = ?, override_at = ? "
                "WHERE ioc = ?", (verdict, reason, timestamp, ioc),
            )
            self.conn.execute(
                "INSERT INTO indicator_events(ioc, event_type, data_json, created_at) VALUES (?, ?, ?, ?)",
                (ioc, "verdict_override_set", json.dumps(data, sort_keys=True), timestamp),
            )
            self.conn.commit()
        return self.indicator(ioc)

    def clear_verdict_override(self, ioc: str) -> dict[str, Any] | None:
        """Clear an analyst override while retaining its audit event."""
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self.conn.execute(
                "SELECT verdict_override FROM indicators WHERE ioc = ?", (ioc,)
            ).fetchone()
            if not row:
                return None
            if row["verdict_override"] is not None:
                self.conn.execute(
                    "UPDATE indicators SET verdict_override = NULL, override_reason = NULL, "
                    "override_at = NULL WHERE ioc = ?", (ioc,),
                )
                self.conn.execute(
                    "INSERT INTO indicator_events(ioc, event_type, data_json, created_at) VALUES (?, ?, ?, ?)",
                    (ioc, "verdict_override_cleared", "{}", timestamp),
                )
                self.conn.commit()
        return self.indicator(ioc)

    def create_investigation(self, title: str, description: str = "") -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cursor = self.conn.execute(
                "INSERT INTO investigations(title, description, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (title.strip(), description.strip(), timestamp, timestamp),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("failed to create investigation")
            investigation_id = int(cursor.lastrowid)
            self._record_investigation_event(
                investigation_id, "investigation_created", {"title": title.strip()}, timestamp
            )
            self.conn.commit()
        return self.investigation(investigation_id) or {}

    def investigation(self, investigation_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if not row:
                return None
            indicators = self.conn.execute(
                "SELECT ioc FROM investigation_indicators WHERE investigation_id = ? "
                "ORDER BY added_at", (investigation_id,)
            ).fetchall()
        result = dict(row)
        result["indicators"] = [item["ioc"] for item in indicators]
        return result

    def list_investigations(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM investigations ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        investigations = []
        for row in rows:
            investigation = self.investigation(row["id"])
            if investigation is not None:
                investigations.append(investigation)
        return investigations

    def add_investigation_indicator(
        self, investigation_id: int, ioc: str
    ) -> dict[str, Any] | None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            exists = self.conn.execute(
                "SELECT id FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if not exists:
                return None
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO investigation_indicators(investigation_id, ioc, added_at) "
                "VALUES (?, ?, ?)",
                (investigation_id, ioc, timestamp),
            )
            if cursor.rowcount:
                self._record_investigation_event(
                    investigation_id, "indicator_added", {"ioc": ioc}, timestamp
                )
            self.conn.execute(
                "UPDATE investigations SET updated_at = ? WHERE id = ?",
                (timestamp, investigation_id),
            )
            self.conn.commit()
        return self.investigation(investigation_id)

    def investigation_events(
        self, investigation_id: int, limit: int = 100
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, event_type, data_json, created_at FROM investigation_events "
                "WHERE investigation_id = ? ORDER BY id DESC LIMIT ?",
                (investigation_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "data": json.loads(row["data_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def _record_investigation_event(
        self, investigation_id: int, event_type: str, data: dict[str, Any], timestamp: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO investigation_events(investigation_id, event_type, data_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (investigation_id, event_type, json.dumps(data, sort_keys=True), timestamp),
        )

    def add_relationship(
        self,
        source_ioc: str,
        target_ioc: str,
        relationship_type: str,
        confidence: float = 1.0,
        evidence_source: str = "analyst",
    ) -> dict[str, Any]:
        if source_ioc == target_ioc:
            raise ValueError("an indicator cannot relate to itself")
        if not 0 <= confidence <= 1:
            raise ValueError("relationship confidence must be between 0 and 1")
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO indicator_relationships(
                    source_ioc, target_ioc, relationship_type, confidence, evidence_source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_ioc,
                    target_ioc,
                    relationship_type.strip(),
                    confidence,
                    evidence_source.strip() or "analyst",
                    timestamp,
                ),
            )
            self.conn.commit()
            row = self.conn.execute(
                """
                SELECT * FROM indicator_relationships
                WHERE source_ioc = ? AND target_ioc = ? AND relationship_type = ?
                  AND evidence_source = ?
                """,
                (source_ioc, target_ioc, relationship_type.strip(), evidence_source.strip() or "analyst"),
            ).fetchone()
        return dict(row)

    def relationships(self, ioc: str, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT * FROM indicator_relationships
                WHERE source_ioc = ? OR target_ioc = ?
                ORDER BY id DESC LIMIT ?
                """,
                (ioc, ioc, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def relationship_graph(self, ioc: str, limit: int = 100) -> dict[str, Any]:
        edges = self.relationships(ioc, limit=limit)
        nodes = sorted({ioc, *(edge["source_ioc"] for edge in edges),
                        *(edge["target_ioc"] for edge in edges)})
        return {"nodes": [{"id": node} for node in nodes], "edges": edges}

    def close(self) -> None:
        self.conn.close()
