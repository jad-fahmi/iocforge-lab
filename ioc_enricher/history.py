"""Durable SQLite history for enrichment investigations."""

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import METHODOLOGY_VERSION, score

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
            if 6 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE evidence_observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        observation_key TEXT NOT NULL UNIQUE,
                        source TEXT NOT NULL,
                        ioc TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        collected_at TEXT NOT NULL,
                        observed_at TEXT,
                        raw_response_sha256 TEXT NOT NULL,
                        connector_version TEXT NOT NULL,
                        normalization_version TEXT NOT NULL,
                        observation_json TEXT NOT NULL
                    );
                    CREATE INDEX idx_evidence_ioc_time
                    ON evidence_observations(ioc, collected_at DESC);
                    CREATE INDEX idx_evidence_source_ioc_time
                    ON evidence_observations(source, ioc, collected_at DESC);
                    CREATE TABLE enrichment_observations (
                        enrichment_id INTEGER NOT NULL,
                        observation_id INTEGER NOT NULL,
                        ordinal INTEGER NOT NULL,
                        PRIMARY KEY(enrichment_id, ordinal),
                        FOREIGN KEY(enrichment_id) REFERENCES enrichments(id),
                        FOREIGN KEY(observation_id) REFERENCES evidence_observations(id)
                    );
                    CREATE INDEX idx_enrichment_observations_observation
                    ON enrichment_observations(observation_id, enrichment_id);
                    """
                )
                # Enrichments predating this schema version keep their original
                # snapshots and gain normalized evidence rows during migration.
                prior = self.conn.execute(
                    "SELECT id, looked_up_at, result_json FROM enrichments ORDER BY id"
                ).fetchall()
                for row in prior:
                    for ordinal, source in enumerate(
                        json.loads(row["result_json"]).get("sources", [])
                    ):
                        migrated_source = dict(source)
                        migrated_source.setdefault("collected_at", row["looked_up_at"])
                        self._store_observation(
                            migrated_source, row["id"], ordinal
                        )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (6)")
            if 7 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE enrichment_observations_v7 (
                        enrichment_id INTEGER NOT NULL,
                        observation_id INTEGER NOT NULL,
                        ordinal INTEGER NOT NULL,
                        PRIMARY KEY(enrichment_id, ordinal),
                        FOREIGN KEY(enrichment_id) REFERENCES enrichments(id),
                        FOREIGN KEY(observation_id) REFERENCES evidence_observations(id)
                    );
                    INSERT INTO enrichment_observations_v7(
                        enrichment_id, observation_id, ordinal
                    ) SELECT enrichment_id, observation_id, ordinal
                      FROM enrichment_observations;
                    DROP TABLE enrichment_observations;
                    ALTER TABLE enrichment_observations_v7
                      RENAME TO enrichment_observations;
                    CREATE INDEX idx_enrichment_observations_observation
                    ON enrichment_observations(observation_id, enrichment_id);
                    """
                )
                # Rebuild links from snapshots so repeated observations within a
                # single enrichment retain their original positions as well.
                self.conn.execute("DELETE FROM enrichment_observations")
                prior = self.conn.execute(
                    "SELECT id, looked_up_at, result_json FROM enrichments ORDER BY id"
                ).fetchall()
                for row in prior:
                    for ordinal, source in enumerate(
                        json.loads(row["result_json"]).get("sources", [])
                    ):
                        migrated_source = dict(source)
                        migrated_source.setdefault("collected_at", row["looked_up_at"])
                        self._store_observation(
                            migrated_source, row["id"], ordinal
                        )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (7)")
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
            enrichment_id = cursor.lastrowid
            if enrichment_id is None:
                raise RuntimeError("failed to persist enrichment history")
            trace_observations = payload.get("decision_trace", {}).get(
                "observations", []
            )
            for ordinal, source in enumerate(payload.get("sources", [])):
                observation_id = self._store_observation(
                    source, enrichment_id, ordinal
                )
                if ordinal < len(trace_observations):
                    trace_observations[ordinal]["observation_id"] = observation_id
            self.conn.execute(
                "UPDATE enrichments SET result_json = ? WHERE id = ?",
                (json.dumps(payload, sort_keys=True), enrichment_id),
            )
            self.conn.commit()
            return int(enrichment_id)

    def _store_observation(
        self, source: dict[str, Any], enrichment_id: int, ordinal: int
    ) -> int:
        """Insert an immutable provider observation and link it to a snapshot."""
        source = dict(source)
        source.setdefault("collected_at", "")
        source.setdefault("connector_version", "unknown")
        source.setdefault("normalization_version", "1")
        raw_sha256 = source.get("raw_response_sha256")
        if not raw_sha256:
            raw = json.dumps(
                source.get("raw", {}),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            raw_sha256 = hashlib.sha256(raw).hexdigest()
            source["raw_response_sha256"] = raw_sha256
        observation_json = json.dumps(
            source, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        identity = {
            "source": source["source"],
            "ioc": source["ioc"],
            "collected_at": source.get("collected_at", ""),
            "raw_response_sha256": raw_sha256,
            "connector_version": source.get("connector_version", "unknown"),
            "normalization_version": source.get("normalization_version", "1"),
        }
        observation_key = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        self.conn.execute(
            """
            INSERT OR IGNORE INTO evidence_observations(
                observation_key, source, ioc, ioc_type, collected_at, observed_at,
                raw_response_sha256, connector_version, normalization_version,
                observation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_key,
                source["source"],
                source["ioc"],
                source["ioc_type"],
                source.get("collected_at", ""),
                source.get("observed_at"),
                raw_sha256,
                source.get("connector_version", "unknown"),
                source.get("normalization_version", "1"),
                observation_json,
            ),
        )
        row = self.conn.execute(
            "SELECT id FROM evidence_observations WHERE observation_key = ?",
            (observation_key,),
        ).fetchone()
        if row is None:
            raise RuntimeError("failed to persist source observation")
        observation_id = int(row["id"])
        self.conn.execute(
            """
            INSERT OR IGNORE INTO enrichment_observations(
                enrichment_id, observation_id, ordinal
            ) VALUES (?, ?, ?)
            """,
            (enrichment_id, observation_id, ordinal),
        )
        return observation_id

    def observations_for_enrichment(self, enrichment_id: int) -> list[dict[str, Any]]:
        """Return stable observation IDs and immutable payloads for a snapshot."""
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT eo.ordinal, obs.id, obs.observation_key, obs.observation_json
                FROM enrichment_observations AS eo
                JOIN evidence_observations AS obs ON obs.id = eo.observation_id
                WHERE eo.enrichment_id = ? ORDER BY eo.ordinal
                """,
                (enrichment_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "observation_key": row["observation_key"],
                "ordinal": row["ordinal"],
                "observation": json.loads(row["observation_json"]),
            }
            for row in rows
        ]

    def replay_enrichment(self, enrichment_id: int) -> dict[str, Any] | None:
        """Re-score a saved enrichment using its observations and pinned config."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM enrichments WHERE id = ?", (enrichment_id,)
            ).fetchone()
        if row is None:
            return None

        original = json.loads(row["result_json"])
        config = original.get("scoring_config")
        scored_at = original.get("scored_at")
        version = original.get("scoring_version")
        if version != METHODOLOGY_VERSION:
            reason = "scoring_methodology_unavailable"
        elif not config or not scored_at:
            reason = "scoring_inputs_missing"
        else:
            reason = None
        observation_rows = self.observations_for_enrichment(enrichment_id)
        if not reason and len(observation_rows) != len(original.get("sources", [])):
            reason = "evidence_observations_missing"
        if reason:
            return {
                "enrichment_id": enrichment_id,
                "replayable": False,
                "reason": reason,
                "original": original,
                "observations": observation_rows,
            }

        sources = []
        for observation_row in observation_rows:
            saved = observation_row["observation"]
            source = dict(saved)
            source["ioc_type"] = IocType(source["ioc_type"])
            sources.append(SourceResult(**source))
        replayed = EnrichmentResult(
            ioc=original["ioc"],
            ioc_type=IocType(original["ioc_type"]),
            sources=sources,
            internal_context=original.get("internal_context", {}),
        )
        score(replayed, settings=config, as_of=scored_at)
        recalculated = replayed.to_dict()
        for ordinal, observation in enumerate(observation_rows):
            trace = recalculated["decision_trace"].get("observations", [])
            if ordinal < len(trace):
                trace[ordinal]["observation_id"] = observation["id"]
        decision_fields = (
            "score",
            "verdict",
            "confidence",
            "evidence",
            "counter_evidence",
            "no_data",
            "errors",
            "reason_codes",
            "recommended_action",
            "decision_trace",
        )
        matches = all(original.get(key) == recalculated.get(key) for key in decision_fields)
        return {
            "enrichment_id": enrichment_id,
            "replayable": True,
            "matches_original": matches,
            "scoring_version": version,
            "scoring_config": config,
            "scored_at": scored_at,
            "original": {
                key: original.get(key)
                for key in decision_fields
            },
            "replayed": {
                key: recalculated.get(key)
                for key in decision_fields
            },
            "observations": observation_rows,
        }

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
            "investigation_counts": {
                row["status"]: row["count"] for row in investigation_rows
            },
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
        if status and status not in {
            "open",
            "triaged",
            "benign",
            "malicious",
            "closed",
        }:
            raise ValueError("invalid indicator status")
        fields: dict[str, Any] = {}
        if tags is not None:
            fields["tags"] = json.dumps(
                sorted({tag.strip().lower() for tag in tags if tag.strip()})
            )
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
            data = {
                "verdict_override": verdict,
                "override_reason": reason,
                "override_at": timestamp,
            }
            self.conn.execute(
                "UPDATE indicators SET verdict_override = ?, override_reason = ?, override_at = ? "
                "WHERE ioc = ?",
                (verdict, reason, timestamp, ioc),
            )
            self.conn.execute(
                "INSERT INTO indicator_events(ioc, event_type, data_json, created_at) VALUES (?, ?, ?, ?)",
                (
                    ioc,
                    "verdict_override_set",
                    json.dumps(data, sort_keys=True),
                    timestamp,
                ),
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
                    "override_at = NULL WHERE ioc = ?",
                    (ioc,),
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
                investigation_id,
                "investigation_created",
                {"title": title.strip()},
                timestamp,
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
                "ORDER BY added_at",
                (investigation_id,),
            ).fetchall()
        result = dict(row)
        result["indicators"] = [item["ioc"] for item in indicators]
        return result

    def list_investigations(
        self, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
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

    def update_investigation(
        self,
        investigation_id: int,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        """Update case metadata and retain an auditable lifecycle event."""
        if status is not None and status not in {"open", "triaged", "closed"}:
            raise ValueError("invalid investigation status")

        fields: dict[str, Any] = {}
        if title is not None:
            title = title.strip()
            if not title:
                raise ValueError("investigation title is required")
            fields["title"] = title
        if description is not None:
            fields["description"] = description.strip()
        if status is not None:
            fields["status"] = status
        if not fields:
            return self.investigation(investigation_id)

        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            existing = self.conn.execute(
                "SELECT id FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if not existing:
                return None
            assignments = ", ".join(f"{field} = ?" for field in fields)
            self.conn.execute(
                f"UPDATE investigations SET {assignments}, updated_at = ? WHERE id = ?",
                [*fields.values(), timestamp, investigation_id],
            )
            event_type = (
                "investigation_status_updated"
                if set(fields) == {"status"}
                else "investigation_updated"
            )
            self._record_investigation_event(
                investigation_id, event_type, fields, timestamp
            )
            self.conn.commit()
        return self.investigation(investigation_id)

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
        self,
        investigation_id: int,
        event_type: str,
        data: dict[str, Any],
        timestamp: str,
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
                (
                    source_ioc,
                    target_ioc,
                    relationship_type.strip(),
                    evidence_source.strip() or "analyst",
                ),
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
        nodes = sorted(
            {
                ioc,
                *(edge["source_ioc"] for edge in edges),
                *(edge["target_ioc"] for edge in edges),
            }
        )
        return {"nodes": [{"id": node} for node in nodes], "edges": edges}

    def close(self) -> None:
        self.conn.close()
