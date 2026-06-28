"""Durable SQLite history for enrichment investigations."""

import hashlib
import json
import logging
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import METHODOLOGY_VERSION, score

DEFAULT_HISTORY_DB = Path.home() / ".local" / "share" / "iocforge-lab" / "history.db"
log = logging.getLogger(__name__)
EVENT_CHAIN_GENESIS = "0" * 64
GRAPH_ENTITY_TYPES = {
    "domain",
    "ip",
    "url",
    "file_hash",
    "asn",
    "certificate",
    "hostname",
    "provider_observation",
    "investigation",
    "email",
    "cve",
    "unknown",
}
HOSTNAME_RELATIONSHIPS = {
    "cname_to",
    "mail_exchange",
    "nameserver",
    "certificate_name",
    "observed_hostname",
    "scan_observed_hostname",
}
PIVOT_ENTITY_WEIGHTS = {
    "certificate": 1.0,
    "ip": 0.95,
    "hostname": 0.9,
    "domain": 0.85,
    "file_hash": 0.8,
    "url": 0.75,
    "asn": 0.7,
    "email": 0.5,
    "cve": 0.5,
}
MAX_PIVOT_PATH_EXPANSIONS = 5000
MAX_PIVOT_ALTERNATIVE_PATHS = 3


def _entity_type_for(
    value: str,
    explicit: str | None = None,
    relationship_type: str | None = None,
    endpoint: str = "",
) -> str:
    if explicit:
        selected = explicit.strip().lower()
        if selected not in GRAPH_ENTITY_TYPES:
            raise ValueError("unsupported graph entity type")
        return selected
    if value.startswith("observation:"):
        return "provider_observation"
    if value.startswith("investigation:"):
        return "investigation"
    detected = detect(value)
    if detected in {IocType.IPV4, IocType.IPV6}:
        return "ip"
    if detected.is_hash():
        return "file_hash"
    if detected == IocType.ASN:
        return "asn"
    if detected == IocType.URL:
        return "url"
    if detected == IocType.DOMAIN:
        if endpoint == "target" and relationship_type in HOSTNAME_RELATIONSHIPS:
            return "hostname"
        return "domain"
    if detected == IocType.EMAIL:
        return "email"
    if detected == IocType.CVE:
        return "cve"
    return "unknown"


def _canonical_entity_value(value: str, entity_type: str) -> str:
    value = refang(value.strip())
    detected = detect(value)
    if entity_type in {"domain", "hostname"} and detected == IocType.DOMAIN:
        return normalize(value, detected)
    if entity_type == "ip" and detected in {IocType.IPV4, IocType.IPV6}:
        return normalize(value, detected)
    if entity_type == "url" and detected == IocType.URL:
        return normalize(value, detected)
    if entity_type == "asn" and detected == IocType.ASN:
        return normalize(value, detected)
    if entity_type == "file_hash" and detected.is_hash():
        return normalize(value, detected)
    if entity_type in {"email", "cve"} and detected != IocType.UNKNOWN:
        return normalize(value, detected)
    return value


def _canonical_relationship_ioc(value: str) -> str:
    """Canonicalize an edge endpoint before comparing or persisting identity."""
    value = refang(value.strip())
    return normalize(value, detect(value))


def _normalize_timestamp(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError, OverflowError) as error:
        raise ValueError("timestamps must use ISO 8601 format") from error
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat()


def _timestamp_value(value: str) -> datetime:
    normalized = _normalize_timestamp(value)
    if normalized is None:
        raise ValueError("timestamp is required")
    return datetime.fromisoformat(normalized)


def _relationship_dict(row: sqlite3.Row) -> dict[str, Any]:
    relationship = dict(row)
    relationship["attributes"] = json.loads(relationship.pop("attributes_json"))
    return relationship


def _event_hash(
    table: str,
    scope_id: str,
    event_id: int,
    event_type: str,
    data_json: str,
    created_at: str,
    previous_hash: str,
) -> str:
    payload = json.dumps(
        {
            "table": table,
            "scope_id": scope_id,
            "id": event_id,
            "event_type": event_type,
            "data_json": data_json,
            "created_at": created_at,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _observation_identity(source: dict[str, Any]) -> dict[str, str]:
    return {
        "source": source["source"],
        "ioc": source["ioc"],
        "collected_at": source.get("collected_at", ""),
        "raw_response_sha256": source["raw_response_sha256"],
        "connector_version": source.get("connector_version", "unknown"),
        "normalization_version": source.get("normalization_version", "1"),
    }


def _observation_key(source: dict[str, Any]) -> str:
    encoded = json.dumps(
        _observation_identity(source), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _observation_content_key(source: dict[str, Any]) -> str:
    """Return a content key used when stable provider identity collides.

    The legacy observation key intentionally groups identical provider payloads
    across repeated lookups. If normalization produces different evidence for
    that same identity, a content key keeps both immutable observations instead
    of silently linking the later snapshot to the first payload.
    """
    stable_source = {
        key: value
        for key, value in source.items()
        if key not in {"latency_ms", "cache_hit"}
    }
    encoded = json.dumps(
        stable_source,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"v2:{hashlib.sha256(encoded).hexdigest()}"


class HistoryStore:
    """Append-only lookup history plus a current indicator index.

    Migrations are tracked in SQLite so new schema versions can be applied
    safely to an analyst's existing local investigation database.
    """

    def __init__(self, path: Path | str = DEFAULT_HISTORY_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
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
            if 8 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE indicator_relationships_v8 (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_ioc TEXT NOT NULL,
                        target_ioc TEXT NOT NULL,
                        relationship_type TEXT NOT NULL,
                        confidence REAL NOT NULL DEFAULT 1.0,
                        evidence_source TEXT NOT NULL DEFAULT 'analyst',
                        created_at TEXT NOT NULL,
                        valid_from TEXT NOT NULL,
                        valid_to TEXT,
                        evidence_observation_id INTEGER,
                        attributes_json TEXT NOT NULL DEFAULT '{}',
                        FOREIGN KEY(evidence_observation_id)
                            REFERENCES evidence_observations(id),
                        CHECK(valid_to IS NULL OR valid_to >= valid_from)
                    );
                    INSERT INTO indicator_relationships_v8(
                        id, source_ioc, target_ioc, relationship_type, confidence,
                        evidence_source, created_at, valid_from
                    ) SELECT id, source_ioc, target_ioc, relationship_type, confidence,
                             evidence_source, created_at, created_at
                      FROM indicator_relationships;
                    DROP TABLE indicator_relationships;
                    ALTER TABLE indicator_relationships_v8
                      RENAME TO indicator_relationships;
                    CREATE INDEX idx_relationships_source
                    ON indicator_relationships(source_ioc);
                    CREATE INDEX idx_relationships_target
                    ON indicator_relationships(target_ioc);
                    CREATE INDEX idx_relationships_evidence
                    ON indicator_relationships(evidence_observation_id);
                    CREATE INDEX idx_relationships_recorded
                    ON indicator_relationships(created_at DESC);
                    CREATE UNIQUE INDEX idx_relationships_evidence_edge
                    ON indicator_relationships(
                        evidence_observation_id, source_ioc, target_ioc,
                        relationship_type, valid_from, COALESCE(valid_to, '')
                    ) WHERE evidence_observation_id IS NOT NULL;
                    CREATE UNIQUE INDEX idx_relationships_analyst_edge
                    ON indicator_relationships(
                        source_ioc, target_ioc, relationship_type, evidence_source,
                        valid_from, COALESCE(valid_to, '')
                    ) WHERE evidence_observation_id IS NULL;
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (8)")
            if 9 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS indicator_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        data_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(ioc) REFERENCES indicators(ioc)
                    );
                    CREATE INDEX IF NOT EXISTS idx_indicator_events_ioc_time
                    ON indicator_events(ioc, created_at DESC);
                    CREATE TABLE IF NOT EXISTS investigation_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        investigation_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        data_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(investigation_id) REFERENCES investigations(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_investigation_events_time
                    ON investigation_events(investigation_id, created_at DESC);
                    ALTER TABLE indicator_events ADD COLUMN previous_hash TEXT;
                    ALTER TABLE indicator_events ADD COLUMN event_hash TEXT;
                    ALTER TABLE investigation_events ADD COLUMN previous_hash TEXT;
                    ALTER TABLE investigation_events ADD COLUMN event_hash TEXT;
                    """
                )
                for table, scope_column in (
                    ("indicator_events", "ioc"),
                    ("investigation_events", "investigation_id"),
                ):
                    groups = self.conn.execute(
                        f"SELECT DISTINCT {scope_column} FROM {table} "
                        f"ORDER BY {scope_column}"
                    ).fetchall()
                    for group in groups:
                        scope_id = str(group[0])
                        prior_hash = EVENT_CHAIN_GENESIS
                        rows = self.conn.execute(
                            f"SELECT id, event_type, data_json, created_at FROM {table} "
                            f"WHERE {scope_column} = ? ORDER BY id",
                            (group[0],),
                        ).fetchall()
                        for row in rows:
                            digest = _event_hash(
                                table,
                                scope_id,
                                row["id"],
                                row["event_type"],
                                row["data_json"],
                                row["created_at"],
                                prior_hash,
                            )
                            self.conn.execute(
                                f"UPDATE {table} SET previous_hash = ?, event_hash = ? "
                                "WHERE id = ?",
                                (prior_hash, digest, row["id"]),
                            )
                            prior_hash = digest
                self.conn.executescript(
                    """
                    CREATE TRIGGER indicator_events_no_update
                    BEFORE UPDATE ON indicator_events
                    BEGIN SELECT RAISE(ABORT, 'indicator events are append-only'); END;
                    CREATE TRIGGER indicator_events_no_delete
                    BEFORE DELETE ON indicator_events
                    BEGIN SELECT RAISE(ABORT, 'indicator events are append-only'); END;
                    CREATE TRIGGER investigation_events_no_update
                    BEFORE UPDATE ON investigation_events
                    BEGIN SELECT RAISE(ABORT, 'investigation events are append-only'); END;
                    CREATE TRIGGER investigation_events_no_delete
                    BEFORE DELETE ON investigation_events
                    BEGIN SELECT RAISE(ABORT, 'investigation events are append-only'); END;
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (9)")
            if 10 not in applied:
                self.conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS investigations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'open',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS investigation_indicators (
                        investigation_id INTEGER NOT NULL,
                        ioc TEXT NOT NULL,
                        added_at TEXT NOT NULL,
                        PRIMARY KEY(investigation_id, ioc),
                        FOREIGN KEY(investigation_id) REFERENCES investigations(id)
                    );
                    CREATE TABLE IF NOT EXISTS graph_entities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entity_type TEXT NOT NULL,
                        canonical_value TEXT NOT NULL,
                        display_value TEXT NOT NULL,
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        UNIQUE(entity_type, canonical_value),
                        CHECK(entity_type IN (
                            'domain', 'ip', 'url', 'file_hash', 'asn',
                            'certificate', 'hostname', 'provider_observation',
                            'investigation', 'email', 'cve', 'unknown'
                        ))
                    );
                    ALTER TABLE indicator_relationships
                      ADD COLUMN source_entity_id INTEGER REFERENCES graph_entities(id);
                    ALTER TABLE indicator_relationships
                      ADD COLUMN target_entity_id INTEGER REFERENCES graph_entities(id);
                    CREATE INDEX idx_relationships_source_entity
                    ON indicator_relationships(source_entity_id);
                    CREATE INDEX idx_relationships_target_entity
                    ON indicator_relationships(target_entity_id);
                    """
                )
                old_edges = self.conn.execute(
                    "SELECT id, source_ioc, target_ioc, relationship_type FROM "
                    "indicator_relationships ORDER BY id"
                ).fetchall()
                for edge in old_edges:
                    source_entity = self._ensure_graph_entity(
                        edge["source_ioc"],
                        _entity_type_for(
                            edge["source_ioc"],
                            relationship_type=edge["relationship_type"],
                            endpoint="source",
                        ),
                    )
                    target_entity = self._ensure_graph_entity(
                        edge["target_ioc"],
                        _entity_type_for(
                            edge["target_ioc"],
                            relationship_type=edge["relationship_type"],
                            endpoint="target",
                        ),
                    )
                    self.conn.execute(
                        "UPDATE indicator_relationships SET source_entity_id = ?, "
                        "target_entity_id = ? WHERE id = ?",
                        (source_entity, target_entity, edge["id"]),
                    )
                observation_rows = self.conn.execute(
                    "SELECT id, observation_key, source, collected_at, "
                    "raw_response_sha256 FROM evidence_observations ORDER BY id"
                ).fetchall()
                for observation in observation_rows:
                    self._ensure_graph_entity(
                        f"observation:{observation['observation_key']}",
                        "provider_observation",
                        {
                            "observation_id": observation["id"],
                            "source": observation["source"],
                            "collected_at": observation["collected_at"],
                            "raw_response_sha256": observation["raw_response_sha256"],
                        },
                    )
                investigation_rows = self.conn.execute(
                    "SELECT id, title, created_at FROM investigations ORDER BY id"
                ).fetchall()
                for investigation_row in investigation_rows:
                    case_node = f"investigation:{investigation_row['id']}"
                    self._ensure_graph_entity(
                        case_node,
                        "investigation",
                        {"title": investigation_row["title"]},
                    )
                    members = self.conn.execute(
                        "SELECT ioc, added_at FROM investigation_indicators "
                        "WHERE investigation_id = ? ORDER BY added_at",
                        (investigation_row["id"],),
                    ).fetchall()
                    for member in members:
                        self._insert_relationship(
                            source_ioc=member["ioc"],
                            target_ioc=case_node,
                            relationship_type="part_of_investigation",
                            confidence=1.0,
                            evidence_source="analyst",
                            valid_from=member["added_at"],
                            recorded_at=member["added_at"],
                            target_entity_type="investigation",
                        )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (10)")
            if 11 not in applied:
                self.conn.executescript(
                    """
                    CREATE TRIGGER IF NOT EXISTS evidence_observations_no_update
                    BEFORE UPDATE ON evidence_observations
                    BEGIN SELECT RAISE(ABORT, 'evidence observations are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS evidence_observations_no_delete
                    BEFORE DELETE ON evidence_observations
                    BEGIN SELECT RAISE(ABORT, 'evidence observations are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS enrichment_observations_no_update
                    BEFORE UPDATE ON enrichment_observations
                    BEGIN SELECT RAISE(ABORT, 'snapshot evidence links are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS enrichment_observations_no_delete
                    BEFORE DELETE ON enrichment_observations
                    BEGIN SELECT RAISE(ABORT, 'snapshot evidence links are append-only'); END;
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (11)")
            if 12 not in applied:
                self.conn.executescript(
                    """
                    CREATE TRIGGER IF NOT EXISTS indicator_relationships_no_update
                    BEFORE UPDATE ON indicator_relationships
                    BEGIN SELECT RAISE(ABORT, 'graph relationships are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS indicator_relationships_no_delete
                    BEFORE DELETE ON indicator_relationships
                    BEGIN SELECT RAISE(ABORT, 'graph relationships are append-only'); END;
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (12)")
            if 13 not in applied:
                self.conn.executescript(
                    """
                    CREATE TRIGGER IF NOT EXISTS enrichments_no_update
                    BEFORE UPDATE ON enrichments
                    BEGIN SELECT RAISE(ABORT, 'enrichment snapshots are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS enrichments_no_delete
                    BEFORE DELETE ON enrichments
                    BEGIN SELECT RAISE(ABORT, 'enrichment snapshots are append-only'); END;
                    """
                )
                self.conn.execute("INSERT INTO schema_migrations(version) VALUES (13)")
            self.conn.commit()

    def _ensure_graph_entity(
        self,
        value: str,
        entity_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        canonical = _canonical_entity_value(value, entity_type)
        metadata_json = json.dumps(
            metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        timestamp = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO graph_entities(entity_type, canonical_value, display_value, "
            "metadata_json, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(entity_type, canonical_value) DO UPDATE SET "
            "metadata_json = excluded.metadata_json "
            "WHERE graph_entities.metadata_json = '{}'",
            (entity_type, canonical, value.strip(), metadata_json, timestamp),
        )
        row = self.conn.execute(
            "SELECT id FROM graph_entities WHERE entity_type = ? AND canonical_value = ?",
            (entity_type, canonical),
        ).fetchone()
        if row is None:
            raise RuntimeError("failed to persist graph entity")
        return int(row["id"])

    def graph_entity(self, entity_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM graph_entities WHERE id = ?", (entity_id,)
            ).fetchone()
        if row is None:
            return None
        entity = dict(row)
        entity["metadata"] = json.loads(entity.pop("metadata_json"))
        return entity

    def _append_audited_event(
        self,
        table: str,
        scope_column: str,
        scope_id: str | int,
        event_type: str,
        data: dict[str, Any],
        timestamp: str,
    ) -> None:
        if (table, scope_column) not in {
            ("indicator_events", "ioc"),
            ("investigation_events", "investigation_id"),
        }:
            raise ValueError("unsupported event log")
        previous = self.conn.execute(
            f"SELECT event_hash FROM {table} WHERE {scope_column} = ? ORDER BY id DESC LIMIT 1",
            (scope_id,),
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else EVENT_CHAIN_GENESIS
        data_json = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        event_id = self.conn.execute(
            f"SELECT COALESCE(MAX(id), 0) + 1 FROM {table}"
        ).fetchone()[0]
        digest = _event_hash(
            table,
            str(scope_id),
            event_id,
            event_type,
            data_json,
            timestamp,
            previous_hash,
        )
        self.conn.execute(
            f"INSERT INTO {table}(id, {scope_column}, event_type, data_json, created_at, "
            "previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                scope_id,
                event_type,
                data_json,
                timestamp,
                previous_hash,
                digest,
            ),
        )

    def _verify_event_chain(
        self, table: str, scope_column: str, scope_id: str | int
    ) -> dict[str, Any]:
        rows = self.conn.execute(
            f"SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
            f"FROM {table} WHERE {scope_column} = ? ORDER BY id",
            (scope_id,),
        ).fetchall()
        previous_hash = EVENT_CHAIN_GENESIS
        first_invalid: int | None = None
        for row in rows:
            expected_hash = _event_hash(
                table,
                str(scope_id),
                row["id"],
                row["event_type"],
                row["data_json"],
                row["created_at"],
                previous_hash,
            )
            if (
                row["previous_hash"] != previous_hash
                or row["event_hash"] != expected_hash
            ):
                first_invalid = row["id"]
                break
            previous_hash = row["event_hash"]
        return {
            "scope_id": scope_id,
            "valid": first_invalid is None,
            "checked_events": len(rows),
            "first_invalid_event_id": first_invalid,
            "head_hash": previous_hash if first_invalid is None else None,
        }

    def verify_indicator_event_chain(self, ioc: str) -> dict[str, Any]:
        with self._lock:
            return self._verify_event_chain("indicator_events", "ioc", ioc)

    def verify_investigation_event_chain(
        self, investigation_id: int
    ) -> dict[str, Any]:
        with self._lock:
            return self._verify_event_chain(
                "investigation_events", "investigation_id", investigation_id
            )

    def record(self, result: Any, looked_up_at: str | None = None) -> int:
        """Persist an immutable enrichment snapshot and update indicator times."""
        timestamp = _normalize_timestamp(
            looked_up_at
            if looked_up_at is not None
            else datetime.now(timezone.utc).isoformat()
        )
        if timestamp is None:
            raise ValueError("looked_up_at timestamp is required")
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
            trace_observations = result.decision_trace.get("observations", [])
            for ordinal, source in enumerate(payload.get("sources", [])):
                observation_id = self._store_observation(
                    source, enrichment_id, ordinal
                )
                observation_row = self.conn.execute(
                    "SELECT observation_key, source, collected_at, raw_response_sha256 "
                    "FROM evidence_observations WHERE id = ?",
                    (observation_id,),
                ).fetchone()
                if observation_row is None:
                    raise RuntimeError("stored observation was not found")
                self._ensure_graph_entity(
                    f"observation:{observation_row['observation_key']}",
                    "provider_observation",
                    {
                        "observation_id": observation_id,
                        "source": observation_row["source"],
                        "collected_at": observation_row["collected_at"],
                        "raw_response_sha256": observation_row[
                            "raw_response_sha256"
                        ],
                    },
                )
                for related in source.get("related_entities", []):
                    if not all(
                        related.get(key)
                        for key in ("source_ioc", "target_ioc", "relationship_type")
                    ):
                        continue
                    try:
                        self._insert_relationship(
                            source_ioc=related["source_ioc"],
                            target_ioc=related["target_ioc"],
                            relationship_type=related["relationship_type"],
                            confidence=related.get("confidence", 1.0),
                            evidence_source=source["source"],
                            evidence_observation_id=observation_id,
                            valid_from=(
                                related.get("valid_from")
                                or related.get("observed_at")
                                or source.get("observed_at")
                                or source.get("collected_at")
                            ),
                            valid_to=related.get("valid_to"),
                            attributes=related.get("attributes", {}),
                            recorded_at=timestamp,
                            source_entity_type=related.get("source_entity_type"),
                            target_entity_type=related.get("target_entity_type"),
                        )
                    except (ValueError, TypeError, AttributeError) as error:
                        log.warning(
                            "skipped malformed relationship from %s: %s",
                            source["source"],
                            error,
                        )
                if ordinal < len(trace_observations):
                    trace_observations[ordinal]["observation_id"] = observation_id
            self.conn.commit()
            return int(enrichment_id)

    def _store_observation(
        self, source: dict[str, Any], enrichment_id: int, ordinal: int
    ) -> int:
        """Insert an immutable provider observation and link it to a snapshot."""
        source = dict(source)
        # Latency and cache status describe this lookup attempt, not the
        # deduplicated provider payload stored as immutable evidence.
        source.pop("latency_ms", None)
        source.pop("cache_hit", None)
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
        observation_key = _observation_key(source)
        existing = self.conn.execute(
            "SELECT id, observation_json FROM evidence_observations "
            "WHERE observation_key = ?",
            (observation_key,),
        ).fetchone()
        if existing is not None and existing["observation_json"] != observation_json:
            observation_key = _observation_content_key(source)
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
        stored = self.conn.execute(
            "SELECT observation_json FROM evidence_observations WHERE id = ?",
            (observation_id,),
        ).fetchone()
        if stored is None or stored["observation_json"] != observation_json:
            raise RuntimeError("observation key resolved to different evidence")
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

    def _with_observation_ids(
        self, enrichment_id: int, result: dict[str, Any]
    ) -> dict[str, Any]:
        """Add normalized evidence IDs to a returned decision trace."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT observation_id, ordinal FROM enrichment_observations "
                "WHERE enrichment_id = ? ORDER BY ordinal",
                (enrichment_id,),
            ).fetchall()
        trace = result.get("decision_trace", {}).get("observations", [])
        if not isinstance(trace, list):
            return result
        for row in rows:
            ordinal = row["ordinal"]
            if ordinal < len(trace) and isinstance(trace[ordinal], dict):
                trace[ordinal]["observation_id"] = row["observation_id"]
        return result

    def verify_evidence_integrity(
        self,
        iocs: list[str] | None = None,
        enrichment_id: int | None = None,
    ) -> dict[str, Any]:
        """Validate evidence hashes, identities, and snapshot-to-evidence links."""
        issues: list[dict[str, Any]] = []
        checked_observations = 0
        checked_links = 0
        requested_iocs = None if iocs is None else sorted(set(iocs))

        with self._lock:
            if enrichment_id is not None:
                selected = self.conn.execute(
                    "SELECT ioc FROM enrichments WHERE id = ?", (enrichment_id,)
                ).fetchone()
                if selected is None:
                    return {
                        "valid": False,
                        "checked_observations": 0,
                        "checked_snapshot_links": 0,
                        "issues": [
                            {
                                "kind": "snapshot",
                                "enrichment_id": enrichment_id,
                                "problems": ["snapshot_not_found"],
                            }
                        ],
                    }
                if requested_iocs is None:
                    requested_iocs = [selected["ioc"]]
                elif selected["ioc"] not in requested_iocs:
                    return {
                        "valid": False,
                        "checked_observations": 0,
                        "checked_snapshot_links": 0,
                        "issues": [
                            {
                                "kind": "snapshot",
                                "enrichment_id": enrichment_id,
                                "problems": ["snapshot_indicator_scope_mismatch"],
                            }
                        ],
                    }

            if requested_iocs == []:
                return {
                    "valid": True,
                    "checked_observations": 0,
                    "checked_snapshot_links": 0,
                    "issues": [],
                }

            filters = []
            parameters: list[Any] = []
            if requested_iocs is not None:
                placeholders = ",".join("?" for _ in requested_iocs)
                filters.append(f"ioc IN ({placeholders})")
                parameters.extend(requested_iocs)
            if enrichment_id is not None:
                filters.append(
                    "id IN (SELECT observation_id FROM enrichment_observations "
                    "WHERE enrichment_id = ?)"
                )
                parameters.append(enrichment_id)
            where = f" WHERE {' AND '.join(filters)}" if filters else ""
            observations = self.conn.execute(
                "SELECT id, observation_key, source, ioc, ioc_type, collected_at, "
                "observed_at, raw_response_sha256, connector_version, "
                "normalization_version, observation_json FROM evidence_observations"
                + where
                + " ORDER BY id",
                parameters,
            ).fetchall()

            for row in observations:
                checked_observations += 1
                problems: list[str] = []
                try:
                    payload = json.loads(row["observation_json"])
                except (TypeError, json.JSONDecodeError):
                    payload = None
                    problems.append("observation_json_invalid")
                if not isinstance(payload, dict):
                    problems.append("observation_payload_not_object")
                else:
                    for field in (
                        "source",
                        "ioc",
                        "ioc_type",
                        "collected_at",
                        "observed_at",
                        "raw_response_sha256",
                        "connector_version",
                        "normalization_version",
                    ):
                        if payload.get(field) != row[field]:
                            problems.append(f"column_mismatch:{field}")
                    for field in ("collected_at", "observed_at"):
                        value = payload.get(field)
                        if value is None and field == "observed_at":
                            continue
                        if not isinstance(value, str):
                            problems.append(f"{field}_invalid")
                            continue
                        try:
                            _timestamp_value(value)
                        except (TypeError, ValueError, OverflowError):
                            problems.append(f"{field}_invalid")
                    raw = payload.get("raw", {})
                    if not isinstance(raw, dict):
                        problems.append("raw_payload_not_object")
                    else:
                        canonical_raw = json.dumps(
                            raw,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ).encode("utf-8")
                        actual_raw_hash = hashlib.sha256(canonical_raw).hexdigest()
                        if actual_raw_hash != row["raw_response_sha256"]:
                            problems.append("raw_response_hash_mismatch")
                    try:
                        valid_keys = {
                            _observation_key(payload),
                            _observation_content_key(payload),
                        }
                        if row["observation_key"] not in valid_keys:
                            problems.append("observation_key_mismatch")
                    except (KeyError, TypeError, ValueError):
                        problems.append("observation_identity_invalid")
                if problems:
                    issues.append(
                        {
                            "kind": "observation",
                            "observation_id": row["id"],
                            "problems": sorted(set(problems)),
                        }
                    )

            snapshot_filters = []
            snapshot_parameters: list[Any] = []
            if requested_iocs is not None:
                placeholders = ",".join("?" for _ in requested_iocs)
                snapshot_filters.append(f"ioc IN ({placeholders})")
                snapshot_parameters.extend(requested_iocs)
            if enrichment_id is not None:
                snapshot_filters.append("id = ?")
                snapshot_parameters.append(enrichment_id)
            snapshot_where = (
                f" WHERE {' AND '.join(snapshot_filters)}" if snapshot_filters else ""
            )
            snapshots = self.conn.execute(
                "SELECT id, ioc, looked_up_at, result_json FROM enrichments"
                + snapshot_where
                + " ORDER BY id",
                snapshot_parameters,
            ).fetchall()
            for snapshot in snapshots:
                try:
                    snapshot_payload = json.loads(snapshot["result_json"])
                except (TypeError, json.JSONDecodeError):
                    issues.append(
                        {
                            "kind": "snapshot",
                            "enrichment_id": snapshot["id"],
                            "problems": ["snapshot_json_invalid"],
                        }
                    )
                    continue
                if not isinstance(snapshot_payload, dict):
                    issues.append(
                        {
                            "kind": "snapshot",
                            "enrichment_id": snapshot["id"],
                            "problems": ["snapshot_payload_not_object"],
                        }
                    )
                    continue
                sources = snapshot_payload.get("sources", [])
                if not isinstance(sources, list):
                    issues.append(
                        {
                            "kind": "snapshot",
                            "enrichment_id": snapshot["id"],
                            "problems": ["snapshot_sources_invalid"],
                        }
                    )
                    continue
                links = self.conn.execute(
                    "SELECT eo.ordinal, eo.observation_id, obs.observation_json, "
                    "obs.ioc AS observation_ioc, obs.collected_at "
                    "FROM enrichment_observations AS eo "
                    "LEFT JOIN evidence_observations AS obs "
                    "ON obs.id = eo.observation_id WHERE eo.enrichment_id = ? "
                    "ORDER BY eo.ordinal",
                    (snapshot["id"],),
                ).fetchall()
                checked_links += len(links)
                links_by_ordinal = {row["ordinal"]: row for row in links}
                decision_trace = snapshot_payload.get("decision_trace", {})
                trace = (
                    decision_trace.get("observations", [])
                    if isinstance(decision_trace, dict)
                    else []
                )
                if isinstance(trace, list):
                    for ordinal, trace_item in enumerate(trace):
                        link = links_by_ordinal.get(ordinal)
                        if (
                            isinstance(trace_item, dict)
                            and "observation_id" in trace_item
                            and link is not None
                            and trace_item["observation_id"] != link["observation_id"]
                        ):
                            issues.append(
                                {
                                    "kind": "snapshot_link",
                                    "enrichment_id": snapshot["id"],
                                    "ordinal": ordinal,
                                    "problems": ["decision_trace_observation_id_mismatch"],
                                }
                            )
                for ordinal, source in enumerate(sources):
                    link = links_by_ordinal.get(ordinal)
                    problems = []
                    if not isinstance(source, dict):
                        problems.append("snapshot_source_not_object")
                    if link is None:
                        problems.append("evidence_link_missing")
                    elif link["observation_json"] is None:
                        problems.append("linked_observation_missing")
                    elif link["observation_ioc"] != snapshot["ioc"]:
                        problems.append("linked_observation_indicator_mismatch")
                    elif isinstance(source, dict):
                        try:
                            snapshot_time = _timestamp_value(snapshot["looked_up_at"])
                            collected_time = _timestamp_value(link["collected_at"])
                            if collected_time > snapshot_time:
                                problems.append("observation_collected_after_snapshot")
                        except (TypeError, ValueError, OverflowError):
                            problems.append("snapshot_or_observation_timestamp_invalid")
                        try:
                            evidence_payload = json.loads(link["observation_json"])
                        except (TypeError, json.JSONDecodeError):
                            evidence_payload = None
                            problems.append("linked_observation_json_invalid")
                        if isinstance(evidence_payload, dict):
                            snapshot_source = dict(source)
                            snapshot_source.pop("latency_ms", None)
                            snapshot_source.pop("cache_hit", None)
                            # Migrations add provenance defaults to old evidence
                            # rows while leaving the original snapshot untouched.
                            snapshot_source.setdefault(
                                "collected_at", snapshot["looked_up_at"]
                            )
                            snapshot_source.setdefault(
                                "raw_response_sha256",
                                evidence_payload.get("raw_response_sha256"),
                            )
                            snapshot_source.setdefault("connector_version", "unknown")
                            snapshot_source.setdefault("normalization_version", "1")
                            if snapshot_source != evidence_payload:
                                problems.append("snapshot_source_mismatch")
                    if problems:
                        issues.append(
                            {
                                "kind": "snapshot_link",
                                "enrichment_id": snapshot["id"],
                                "ordinal": ordinal,
                                "problems": sorted(set(problems)),
                            }
                        )
                for ordinal, _link in links_by_ordinal.items():
                    if ordinal < 0 or ordinal >= len(sources):
                        issues.append(
                            {
                                "kind": "snapshot_link",
                                "enrichment_id": snapshot["id"],
                                "ordinal": ordinal,
                                "problems": ["snapshot_source_missing"],
                            }
                        )

        return {
            "valid": not issues,
            "checked_observations": checked_observations,
            "checked_snapshot_links": checked_links,
            "issues": issues,
        }

    def replay_enrichment(self, enrichment_id: int) -> dict[str, Any] | None:
        """Re-score a saved enrichment using its observations and pinned config."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM enrichments WHERE id = ?", (enrichment_id,)
            ).fetchone()
        if row is None:
            return None

        original = self._with_observation_ids(
            enrichment_id, json.loads(row["result_json"])
        )
        evidence_integrity = self.verify_evidence_integrity(
            iocs=[original["ioc"]], enrichment_id=enrichment_id
        )
        if not evidence_integrity["valid"]:
            return {
                "enrichment_id": enrichment_id,
                "replayable": False,
                "reason": "evidence_integrity_failed",
                "evidence_integrity": evidence_integrity,
                "original": original,
                "observations": self.observations_for_enrichment(enrichment_id),
            }
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
                "evidence_integrity": evidence_integrity,
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
            ioc_normalization_version=original.get("ioc_normalization_version", "1"),
            sources=sources,
            unavailable_providers=original.get("unavailable_providers", []),
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
            "evidence_integrity": evidence_integrity,
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

    def replay_investigation(
        self, investigation_id: int, as_of: str
    ) -> dict[str, Any] | None:
        """Reconstruct case membership, decisions, analyst state, and graph at a time."""
        timestamp = _normalize_timestamp(as_of)
        if timestamp is None:
            raise ValueError("as_of timestamp is required")
        at = _timestamp_value(timestamp)
        with self._lock:
            investigation_row = self.conn.execute(
                "SELECT id FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            event_rows = self.conn.execute(
                "SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
                "FROM investigation_events WHERE investigation_id = ? ORDER BY id",
                (investigation_id,),
            ).fetchall()
        if investigation_row is None:
            return None

        def historical_events(
            rows: list[sqlite3.Row], table: str, scope_id: str | int
        ) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
            eligible = []
            timestamp_errors = []
            for row in rows:
                event = dict(row)
                try:
                    event_time = _timestamp_value(event["created_at"])
                except (TypeError, ValueError, OverflowError):
                    timestamp_errors.append(event["id"])
                    continue
                if event_time <= at:
                    eligible.append(event)
            previous_hash = EVENT_CHAIN_GENESIS
            first_invalid = None
            events = []
            state_complete = not timestamp_errors
            for event in eligible:
                expected_hash = _event_hash(
                    table,
                    str(scope_id),
                    event["id"],
                    event["event_type"],
                    event["data_json"],
                    event["created_at"],
                    previous_hash,
                )
                if (
                    event["previous_hash"] != previous_hash
                    or event["event_hash"] != expected_hash
                ):
                    first_invalid = event["id"]
                    state_complete = False
                    break
                previous_hash = event["event_hash"]
                try:
                    data = json.loads(event.pop("data_json"))
                except (TypeError, ValueError):
                    state_complete = False
                    first_invalid = event["id"]
                    break
                if not isinstance(data, dict):
                    state_complete = False
                    first_invalid = event["id"]
                    break
                event["data"] = data
                events.append(event)
            return (
                events,
                {
                    "scope_id": scope_id,
                    "valid": first_invalid is None and not timestamp_errors,
                    "checked_events": len(eligible),
                    "first_invalid_event_id": first_invalid,
                    "unparseable_timestamp_event_ids": timestamp_errors,
                    "head_hash": previous_hash if first_invalid is None else None,
                },
                state_complete,
            )

        case_events, case_integrity, case_state_complete = historical_events(
            event_rows, "investigation_events", investigation_id
        )
        investigation_state: dict[str, Any] = {
            "id": investigation_id,
            "title": None,
            "description": None,
            "status": None,
        }
        members: dict[str, str] = {}
        exists_at_time = False
        metadata_complete = False
        for event in case_events:
            data = event["data"]
            if event["event_type"] == "investigation_created":
                exists_at_time = True
                investigation_state.update(
                    {key: data[key] for key in ("title", "description", "status") if key in data}
                )
                metadata_complete = all(
                    key in data for key in ("title", "description", "status")
                )
            elif event["event_type"] in {
                "investigation_updated",
                "investigation_status_updated",
            }:
                investigation_state.update(
                    {key: data[key] for key in ("title", "description", "status") if key in data}
                )
            elif event["event_type"] == "indicator_added" and isinstance(
                data.get("ioc"), str
            ):
                members.setdefault(data["ioc"], event["created_at"])

        if not exists_at_time:
            creation_status: bool | None = (
                False if case_integrity["valid"] and case_state_complete else None
            )
            return {
                "investigation_id": investigation_id,
                "as_of": timestamp,
                "exists_at_time": creation_status,
                "replayable": False,
                "reason": (
                    "investigation_not_yet_created"
                    if creation_status is False
                    else "investigation_creation_event_untrusted"
                ),
                "state_complete": False,
                "event_integrity": case_integrity,
            }

        indicator_states: list[dict[str, Any]] = []
        event_integrity = {"investigation": case_integrity, "indicators": {}}
        state_complete = case_state_complete and metadata_complete
        for ioc, added_at in members.items():
            with self._lock:
                indicator_rows = self.conn.execute(
                    "SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
                    "FROM indicator_events WHERE ioc = ? ORDER BY id",
                    (ioc,),
                ).fetchall()
                snapshots = self.conn.execute(
                    "SELECT id, verdict, score, confidence, looked_up_at FROM enrichments "
                    "WHERE ioc = ? ORDER BY id",
                    (ioc,),
                ).fetchall()
            events, integrity, indicator_state_complete = historical_events(
                indicator_rows, "indicator_events", ioc
            )
            event_integrity["indicators"][ioc] = integrity
            state_complete = state_complete and indicator_state_complete
            indicator_state: dict[str, Any] = {
                "status": "open",
                "tags": [],
                "analyst_notes": "",
                "verdict_override": None,
                "override_reason": None,
                "override_at": None,
            }
            for event in events:
                data = event["data"]
                if event["event_type"] == "indicator_updated":
                    for key in ("status", "analyst_notes"):
                        if key in data:
                            indicator_state[key] = data[key]
                    if "tags" in data:
                        try:
                            tags = json.loads(data["tags"])
                        except (TypeError, ValueError):
                            state_complete = False
                        else:
                            if isinstance(tags, list) and all(
                                isinstance(tag, str) for tag in tags
                            ):
                                indicator_state["tags"] = tags
                            else:
                                state_complete = False
                elif event["event_type"] == "verdict_override_set":
                    indicator_state.update(
                        {
                            "verdict_override": data.get("verdict_override"),
                            "override_reason": data.get("override_reason"),
                            "override_at": data.get("override_at"),
                        }
                    )
                elif event["event_type"] == "verdict_override_cleared":
                    indicator_state.update(
                        {
                            "verdict_override": None,
                            "override_reason": None,
                            "override_at": None,
                        }
                    )

            eligible_snapshots = []
            invalid_snapshot_times = []
            for snapshot in snapshots:
                try:
                    snapshot_time = _timestamp_value(snapshot["looked_up_at"])
                except (TypeError, ValueError, OverflowError):
                    invalid_snapshot_times.append(snapshot["id"])
                    continue
                if snapshot_time <= at:
                    eligible_snapshots.append((snapshot_time, snapshot))
            eligible_snapshots.sort(key=lambda item: (item[0], item[1]["id"]))
            latest = eligible_snapshots[-1][1] if eligible_snapshots else None
            if invalid_snapshot_times:
                state_complete = False
            replay = (
                self.replay_enrichment(int(latest["id"])) if latest is not None else None
            )
            indicator_states.append(
                {
                    "ioc": ioc,
                    "added_at": added_at,
                    "analyst_state": indicator_state,
                    "analyst_events": events,
                    "event_integrity": integrity,
                    "invalid_snapshot_timestamp_ids": invalid_snapshot_times,
                    "latest_enrichment": (
                        {
                            "enrichment_id": latest["id"],
                            "looked_up_at": latest["looked_up_at"],
                            "source_verdict": latest["verdict"],
                            "source_score": latest["score"],
                            "replay": replay,
                        }
                        if latest is not None
                        else None
                    ),
                }
            )
        graph = self._relationship_graph_for_roots(
            [self._graph_root(ioc) for ioc in members],
            limit=500,
            max_depth=5,
            as_of=timestamp,
        )

        return {
            "investigation_id": investigation_id,
            "as_of": timestamp,
            "exists_at_time": True,
            "replayable": state_complete
            and all(
                item["latest_enrichment"] is None
                or item["latest_enrichment"]["replay"].get("replayable", False)
                for item in indicator_states
            ),
            "state_complete": state_complete,
            "investigation": investigation_state,
            "events": case_events,
            "indicators": indicator_states,
            "indicator_count": len(indicator_states),
            "graph": {
                "nodes": graph["nodes"],
                "edges": graph["edges"],
                "max_depth": 5,
                "edge_limit": 500,
                "truncated": graph["truncated"],
                "as_of": timestamp,
            },
            "event_integrity": event_integrity,
            "methodology": "investigation_event_prefix_and_snapshot_replay_v1",
        }

    def compare_investigations(
        self, investigation_id: int, baseline_as_of: str, comparison_as_of: str
    ) -> dict[str, Any] | None:
        """Explain how a reconstructed investigation changed between two times."""
        baseline_time = _normalize_timestamp(baseline_as_of)
        comparison_time = _normalize_timestamp(comparison_as_of)
        if baseline_time is None or comparison_time is None:
            raise ValueError("both comparison timestamps are required")
        if _timestamp_value(comparison_time) < _timestamp_value(baseline_time):
            raise ValueError("comparison time must not precede the baseline")
        baseline = self.replay_investigation(investigation_id, baseline_time)
        comparison = self.replay_investigation(investigation_id, comparison_time)
        if baseline is None or comparison is None:
            return None

        before = {item["ioc"]: item for item in baseline.get("indicators", [])}
        after = {item["ioc"]: item for item in comparison.get("indicators", [])}
        before_iocs, after_iocs = set(before), set(after)
        indicator_deltas = []
        for ioc in sorted(before_iocs | after_iocs):
            earlier = before.get(ioc)
            later = after.get(ioc)
            before_latest = earlier.get("latest_enrichment") if earlier else None
            after_latest = later.get("latest_enrichment") if later else None

            def observations_for(latest: dict[str, Any] | None) -> dict[int, dict[str, Any]]:
                if latest is None or latest.get("replay") is None:
                    return {}
                return {
                    item["id"]: item
                    for item in latest["replay"].get("observations", [])
                    if isinstance(item.get("id"), int)
                }

            before_observations = observations_for(before_latest)
            after_observations = observations_for(after_latest)
            before_ids, after_ids = set(before_observations), set(after_observations)
            before_replay = before_latest.get("replay") if before_latest else None
            after_replay = after_latest.get("replay") if after_latest else None

            def contributions(replay: dict[str, Any] | None) -> dict[int, dict[str, Any]]:
                if replay is None:
                    return {}
                result = replay.get("replayed") if replay.get("replayable") else replay.get("original")
                trace = result.get("decision_trace", {}) if isinstance(result, dict) else {}
                return {
                    item["observation_id"]: item
                    for item in trace.get("observations", [])
                    if isinstance(item.get("observation_id"), int)
                }

            before_trace = contributions(before_replay)
            after_trace = contributions(after_replay)

            def evidence_rows(
                observation_ids: set[int],
                observations: dict[int, dict[str, Any]],
                trace: dict[int, dict[str, Any]],
            ) -> list[dict[str, Any]]:
                return [
                    {
                        **observations[observation_id],
                        "decision_contribution": trace.get(observation_id),
                    }
                    for observation_id in sorted(observation_ids)
                ]

            before_events = {
                item["id"]: item for item in (earlier or {}).get("analyst_events", [])
            }
            after_events = {
                item["id"]: item for item in (later or {}).get("analyst_events", [])
            }
            before_state = earlier.get("analyst_state") if earlier else None
            after_state = later.get("analyst_state") if later else None
            before_verdict = before_latest.get("source_verdict") if before_latest else None
            after_verdict = after_latest.get("source_verdict") if after_latest else None
            before_score = before_latest.get("source_score") if before_latest else None
            after_score = after_latest.get("source_score") if after_latest else None
            indicator_deltas.append(
                {
                    "ioc": ioc,
                    "membership": (
                        "added"
                        if earlier is None
                        else "removed"
                        if later is None
                        else "retained"
                    ),
                    "baseline": {
                        "added_at": earlier.get("added_at") if earlier else None,
                        "latest_enrichment": before_latest,
                        "analyst_state": before_state,
                    },
                    "comparison": {
                        "added_at": later.get("added_at") if later else None,
                        "latest_enrichment": after_latest,
                        "analyst_state": after_state,
                    },
                    "decision": {
                        "verdict_changed": before_verdict != after_verdict,
                        "baseline_verdict": before_verdict,
                        "comparison_verdict": after_verdict,
                        "score_delta": (
                            round(float(after_score) - float(before_score), 3)
                            if before_score is not None and after_score is not None
                            else None
                        ),
                        "baseline_replay_matches": (
                            before_replay.get("matches_original")
                            if before_replay and before_replay.get("replayable")
                            else None
                        ),
                        "comparison_replay_matches": (
                            after_replay.get("matches_original")
                            if after_replay and after_replay.get("replayable")
                            else None
                        ),
                    },
                    "analyst_state_changed": before_state != after_state,
                    "evidence": {
                        "added": evidence_rows(
                            after_ids - before_ids, after_observations, after_trace
                        ),
                        "absent_from_later_snapshot": evidence_rows(
                            before_ids - after_ids, before_observations, before_trace
                        ),
                        "unchanged_observation_ids": sorted(before_ids & after_ids),
                        "decision_contribution_changes": [
                            {
                                "observation_id": observation_id,
                                "baseline": before_trace.get(observation_id),
                                "comparison": after_trace.get(observation_id),
                            }
                            for observation_id in sorted(before_ids & after_ids)
                            if before_trace.get(observation_id)
                            != after_trace.get(observation_id)
                        ],
                    },
                    "analyst_events_added": [
                        after_events[event_id]
                        for event_id in sorted(after_events.keys() - before_events.keys())
                    ],
                }
            )

        before_graph = {
            item["id"]: item for item in baseline.get("graph", {}).get("edges", [])
        }
        after_graph = {
            item["id"]: item for item in comparison.get("graph", {}).get("edges", [])
        }
        baseline_case_events = {
            item["id"]: item for item in baseline.get("events", [])
        }
        comparison_case_events = {
            item["id"]: item for item in comparison.get("events", [])
        }
        baseline_metadata = baseline.get("investigation", {})
        comparison_metadata = comparison.get("investigation", {})
        metadata_changes = {
            key: {
                "baseline": baseline_metadata.get(key),
                "comparison": comparison_metadata.get(key),
            }
            for key in ("title", "description", "status")
            if baseline_metadata.get(key) != comparison_metadata.get(key)
        }

        def state_summary(state: dict[str, Any]) -> dict[str, Any]:
            return {
                "as_of": state["as_of"],
                "exists_at_time": state["exists_at_time"],
                "investigation": state.get("investigation"),
                "indicator_count": state.get("indicator_count", 0),
                "state_complete": state.get("state_complete", False),
                "replayable": state.get("replayable", False),
                "event_integrity": state.get("event_integrity"),
                "graph_truncated": state.get("graph", {}).get("truncated", False),
            }

        return {
            "investigation_id": investigation_id,
            "baseline": state_summary(baseline),
            "comparison": state_summary(comparison),
            "metadata_changes": metadata_changes,
            "membership": {
                "added": sorted(after_iocs - before_iocs),
                "removed": sorted(before_iocs - after_iocs),
                "retained": sorted(before_iocs & after_iocs),
            },
            "indicators": indicator_deltas,
            "investigation_events_added": [
                comparison_case_events[event_id]
                for event_id in sorted(
                    comparison_case_events.keys() - baseline_case_events.keys()
                )
            ],
            "graph": {
                "added_edges": [
                    after_graph[edge_id]
                    for edge_id in sorted(after_graph.keys() - before_graph.keys())
                ],
                "no_longer_valid_edges": [
                    before_graph[edge_id]
                    for edge_id in sorted(before_graph.keys() - after_graph.keys())
                ],
            },
            "replayable": baseline.get("replayable", False)
            and comparison.get("replayable", False),
            "methodology": "investigation_state_diff_v1",
        }

    def compare_enrichments(
        self,
        baseline_id: int,
        comparison_id: int,
        max_depth: int = 5,
        edge_limit: int = 500,
    ) -> dict[str, Any] | None:
        """Compare evidence, scoring, and graph state between two snapshots."""
        if not 1 <= max_depth <= 5:
            raise ValueError("max_depth must be between 1 and 5")
        if not 1 <= edge_limit <= 500:
            raise ValueError("edge_limit must be between 1 and 500")
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM enrichments WHERE id IN (?, ?)",
                (baseline_id, comparison_id),
            ).fetchall()
        snapshots = {row["id"]: row for row in rows}
        if baseline_id not in snapshots or comparison_id not in snapshots:
            return None
        baseline_row = snapshots[baseline_id]
        comparison_row = snapshots[comparison_id]
        baseline = self._with_observation_ids(
            baseline_id, json.loads(baseline_row["result_json"])
        )
        comparison = self._with_observation_ids(
            comparison_id, json.loads(comparison_row["result_json"])
        )
        if baseline_row["ioc"] != comparison_row["ioc"]:
            raise ValueError("enrichment snapshots must refer to the same IOC")
        baseline_time = _normalize_timestamp(baseline_row["looked_up_at"])
        comparison_time = _normalize_timestamp(comparison_row["looked_up_at"])
        if baseline_time is None or comparison_time is None:
            raise ValueError("enrichment snapshots must have lookup timestamps")
        if comparison_time < baseline_time:
            raise ValueError("comparison snapshot must not precede the baseline")

        baseline_observations = self.observations_for_enrichment(baseline_id)
        comparison_observations = self.observations_for_enrichment(comparison_id)
        baseline_by_id = {item["id"]: item for item in baseline_observations}
        comparison_by_id = {item["id"]: item for item in comparison_observations}
        baseline_ids = set(baseline_by_id)
        comparison_ids = set(comparison_by_id)
        added_ids = comparison_ids - baseline_ids
        removed_ids = baseline_ids - comparison_ids
        shared_ids = baseline_ids & comparison_ids

        baseline_replay = self.replay_enrichment(baseline_id)
        comparison_replay = self.replay_enrichment(comparison_id)
        baseline_trace = {
            item.get("observation_id"): item
            for item in baseline.get("decision_trace", {}).get("observations", [])
            if item.get("observation_id") is not None
        }
        comparison_trace = {
            item.get("observation_id"): item
            for item in comparison.get("decision_trace", {}).get("observations", [])
            if item.get("observation_id") is not None
        }

        def evidence_delta(
            observation_ids: set[int],
            observations: dict[int, dict[str, Any]],
            trace_by_id: dict[int, dict[str, Any]],
        ) -> list[dict[str, Any]]:
            return [
                {
                    **observations[observation_id],
                    "decision_contribution": trace_by_id.get(observation_id),
                }
                for observation_id in sorted(
                    observation_ids,
                    key=lambda item: observations[item]["ordinal"],
                )
            ]

        source_groups: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for side, observations in (
            ("baseline", baseline_observations),
            ("comparison", comparison_observations),
        ):
            for item in observations:
                source = item["observation"]["source"]
                source_groups.setdefault(source, {"baseline": [], "comparison": []})[
                    side
                ].append(item)

        provider_changes = []
        for source, sides in sorted(source_groups.items()):
            before_ids = {item["id"] for item in sides["baseline"]}
            after_ids = {item["id"] for item in sides["comparison"]}
            if before_ids == after_ids:
                continue
            provider_changes.append(
                {
                    "source": source,
                    "baseline": [
                        {
                            "id": item["id"],
                            "ordinal": item["ordinal"],
                            "observation": item["observation"],
                        }
                        for item in sides["baseline"]
                    ],
                    "comparison": [
                        {
                            "id": item["id"],
                            "ordinal": item["ordinal"],
                            "observation": item["observation"],
                        }
                        for item in sides["comparison"]
                    ],
                    "added_observation_ids": sorted(after_ids - before_ids),
                    "removed_from_snapshot_ids": sorted(before_ids - after_ids),
                }
            )

        baseline_graph = self.relationship_graph(
            baseline_row["ioc"],
            limit=edge_limit,
            max_depth=max_depth,
            as_of=baseline_time,
        )
        comparison_graph = self.relationship_graph(
            comparison_row["ioc"],
            limit=edge_limit,
            max_depth=max_depth,
            as_of=comparison_time,
        )

        def edge_key(edge: dict[str, Any]) -> str:
            identity = {
                key: edge.get(key)
                for key in (
                    "source_ioc",
                    "target_ioc",
                    "relationship_type",
                    "confidence",
                    "evidence_source",
                    "evidence_observation_id",
                    "valid_from",
                    "valid_to",
                    "attributes",
                )
            }
            return json.dumps(identity, sort_keys=True, separators=(",", ":"))

        baseline_edges = {edge_key(edge): edge for edge in baseline_graph["edges"]}
        comparison_edges = {
            edge_key(edge): edge for edge in comparison_graph["edges"]
        }
        baseline_nodes = {node["id"] for node in baseline_graph["nodes"]}
        comparison_nodes = {node["id"] for node in comparison_graph["nodes"]}
        score_delta = round(float(comparison["score"]) - float(baseline["score"]), 3)

        return {
            "ioc": baseline_row["ioc"],
            "baseline": {
                "enrichment_id": baseline_id,
                "looked_up_at": baseline_time,
                "verdict": baseline["verdict"],
                "score": baseline["score"],
                "confidence": baseline["confidence"],
                "scoring_version": baseline.get("scoring_version"),
                "scoring_config": baseline.get("scoring_config"),
            },
            "comparison": {
                "enrichment_id": comparison_id,
                "looked_up_at": comparison_time,
                "verdict": comparison["verdict"],
                "score": comparison["score"],
                "confidence": comparison["confidence"],
                "scoring_version": comparison.get("scoring_version"),
                "scoring_config": comparison.get("scoring_config"),
            },
            "verdict_changed": baseline["verdict"] != comparison["verdict"],
            "score_delta": score_delta,
            "scoring_configuration_changed": (
                baseline.get("scoring_version") != comparison.get("scoring_version")
                or baseline.get("scoring_config") != comparison.get("scoring_config")
            ),
            "replay": {
                "baseline_replayable": bool(baseline_replay and baseline_replay["replayable"]),
                "baseline_matches": (
                    baseline_replay.get("matches_original")
                    if baseline_replay and baseline_replay["replayable"]
                    else None
                ),
                "comparison_replayable": bool(
                    comparison_replay and comparison_replay["replayable"]
                ),
                "comparison_matches": (
                    comparison_replay.get("matches_original")
                    if comparison_replay and comparison_replay["replayable"]
                    else None
                ),
            },
            "evidence": {
                "added": evidence_delta(
                    added_ids, comparison_by_id, comparison_trace
                ),
                "removed_from_snapshot": evidence_delta(
                    removed_ids, baseline_by_id, baseline_trace
                ),
                "unchanged_observation_ids": sorted(shared_ids),
                "provider_changes": provider_changes,
            },
            "graph": {
                "baseline": baseline_graph,
                "comparison": comparison_graph,
                "added_edges": [
                    comparison_edges[key]
                    for key in sorted(comparison_edges.keys() - baseline_edges.keys())
                ],
                "removed_edges": [
                    baseline_edges[key]
                    for key in sorted(baseline_edges.keys() - comparison_edges.keys())
                ],
                "added_nodes": sorted(comparison_nodes - baseline_nodes),
                "removed_nodes": sorted(baseline_nodes - comparison_nodes),
            },
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
        items = []
        for row in rows:
            items.append(
                {
                    "id": row["id"],
                    "ioc": row["ioc"],
                    "ioc_type": row["ioc_type"],
                    "verdict": row["verdict"],
                    "score": row["score"],
                    "confidence": row["confidence"],
                    "looked_up_at": row["looked_up_at"],
                    "result": self._with_observation_ids(
                        row["id"], json.loads(row["result_json"])
                    ),
                }
            )
        return items

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
            self._append_audited_event(
                "indicator_events",
                "ioc",
                ioc,
                "indicator_updated",
                fields,
                datetime.now(timezone.utc).isoformat(),
            )
            self.conn.commit()
        return self.indicator(ioc)

    def indicator_events(self, ioc: str, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
                "FROM indicator_events "
                "WHERE ioc = ? ORDER BY id DESC LIMIT ?",
                (ioc, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "data": json.loads(row["data_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
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
            self._append_audited_event(
                "indicator_events",
                "ioc",
                ioc,
                "verdict_override_set",
                data,
                timestamp,
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
                self._append_audited_event(
                    "indicator_events",
                    "ioc",
                    ioc,
                    "verdict_override_cleared",
                    {},
                    timestamp,
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
            self._ensure_graph_entity(
                f"investigation:{investigation_id}",
                "investigation",
                {"title": title.strip()},
            )
            self._record_investigation_event(
                investigation_id,
                "investigation_created",
                {
                    "title": title.strip(),
                    "description": description.strip(),
                    "status": "open",
                },
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

    def investigation_bundle_payload(
        self, investigation_id: int
    ) -> dict[str, Any] | None:
        """Capture case history and its bounded graph for offline replay/export."""
        investigation = self.investigation(investigation_id)
        if investigation is None:
            return None
        iocs = investigation["indicators"]
        snapshots: list[dict[str, Any]] = []
        indicators: dict[str, Any] = {}
        indicator_events: dict[str, list[dict[str, Any]]] = {}
        with self._lock:
            for ioc in iocs:
                indicator_row = self.conn.execute(
                    "SELECT * FROM indicators WHERE ioc = ?", (ioc,)
                ).fetchone()
                if indicator_row:
                    indicator = dict(indicator_row)
                    indicator["tags"] = json.loads(indicator["tags"])
                    indicators[ioc] = indicator
                event_rows = self.conn.execute(
                    "SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
                    "FROM indicator_events WHERE ioc = ? ORDER BY id",
                    (ioc,),
                ).fetchall()
                indicator_events[ioc] = [
                    {
                        **dict(event),
                        "ioc": ioc,
                    }
                    for event in event_rows
                ]
                enrichment_rows = self.conn.execute(
                    "SELECT id, ioc, ioc_type, verdict, score, confidence, looked_up_at, result_json "
                    "FROM enrichments WHERE ioc = ? ORDER BY id",
                    (ioc,),
                ).fetchall()
                for snapshot in enrichment_rows:
                    snapshot_data = dict(snapshot)
                    snapshot_data["result"] = json.loads(
                        snapshot_data.pop("result_json")
                    )
                    snapshots.append(snapshot_data)
            case_events = self.conn.execute(
                "SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
                "FROM investigation_events WHERE investigation_id = ? ORDER BY id",
                (investigation_id,),
            ).fetchall()
            case_events_payload = [
                {**dict(event), "investigation_id": investigation_id}
                for event in case_events
            ]

        for snapshot in snapshots:
            snapshot["result"] = self._with_observation_ids(
                snapshot["id"], snapshot["result"]
            )
            snapshot["observations"] = self.observations_for_enrichment(snapshot["id"])

        edges: dict[int, dict[str, Any]] = {}
        graph_truncated = False
        for ioc in iocs:
            remaining = 500 - len(edges)
            if remaining <= 0:
                graph_truncated = True
                break
            graph = self.relationship_graph(ioc, limit=remaining, max_depth=5)
            edges.update({edge["id"]: edge for edge in graph["edges"]})
            graph_truncated = graph_truncated or graph["truncated"]
        graph_edges = [edges[key] for key in sorted(edges)]
        nodes = sorted(
            {
                *iocs,
                *(edge["source_ioc"] for edge in graph_edges),
                *(edge["target_ioc"] for edge in graph_edges),
            }
        )
        observation_map: dict[int, dict[str, Any]] = {}
        for snapshot in snapshots:
            for observation in snapshot["observations"]:
                observation_map[observation["id"]] = observation
        graph_observation_ids = {
            edge["evidence_observation_id"]
            for edge in graph_edges
            if edge["evidence_observation_id"] is not None
        } - observation_map.keys()
        if graph_observation_ids:
            placeholders = ",".join("?" for _ in graph_observation_ids)
            with self._lock:
                evidence_rows = self.conn.execute(
                    "SELECT id, observation_key, observation_json FROM evidence_observations "
                    f"WHERE id IN ({placeholders})",
                    sorted(graph_observation_ids),
                ).fetchall()
            for row in evidence_rows:
                observation_map[row["id"]] = {
                    "id": row["id"],
                    "observation_key": row["observation_key"],
                    "ordinal": None,
                    "observation": json.loads(row["observation_json"]),
                }
        return {
            "bundle_schema": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "investigation": investigation,
            "indicators": indicators,
            "indicator_events": indicator_events,
            "investigation_events": case_events_payload,
            "snapshots": snapshots,
            "observations": [
                observation_map[key] for key in sorted(observation_map)
            ],
            "graph": {
                "nodes": [{"id": node} for node in nodes],
                "edges": graph_edges,
                "max_depth": 5,
                "edge_limit": 500,
                "truncated": graph_truncated,
            },
        }

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
                self._insert_relationship(
                    source_ioc=ioc,
                    target_ioc=f"investigation:{investigation_id}",
                    relationship_type="part_of_investigation",
                    confidence=1.0,
                    evidence_source="analyst",
                    valid_from=timestamp,
                    recorded_at=timestamp,
                    target_entity_type="investigation",
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
                "SELECT id, event_type, data_json, created_at, previous_hash, event_hash "
                "FROM investigation_events "
                "WHERE investigation_id = ? ORDER BY id DESC LIMIT ?",
                (investigation_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "data": json.loads(row["data_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
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
        self._append_audited_event(
            "investigation_events",
            "investigation_id",
            investigation_id,
            event_type,
            data,
            timestamp,
        )

    def add_relationship(
        self,
        source_ioc: str,
        target_ioc: str,
        relationship_type: str,
        confidence: float = 1.0,
        evidence_source: str = "analyst",
        evidence_observation_id: int | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        attributes: dict[str, Any] | None = None,
        recorded_at: str | None = None,
        source_entity_type: str | None = None,
        target_entity_type: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            edge = self._insert_relationship(
                source_ioc=source_ioc,
                target_ioc=target_ioc,
                relationship_type=relationship_type,
                confidence=confidence,
                evidence_source=evidence_source,
                evidence_observation_id=evidence_observation_id,
                valid_from=valid_from,
                valid_to=valid_to,
                attributes=attributes,
                recorded_at=recorded_at,
                source_entity_type=source_entity_type,
                target_entity_type=target_entity_type,
            )
            self.conn.commit()
            return edge

    def _insert_relationship(
        self,
        source_ioc: str,
        target_ioc: str,
        relationship_type: str,
        confidence: float,
        evidence_source: str,
        evidence_observation_id: int | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        attributes: dict[str, Any] | None = None,
        recorded_at: str | None = None,
        source_entity_type: str | None = None,
        target_entity_type: str | None = None,
    ) -> dict[str, Any]:
        source_ioc = _canonical_relationship_ioc(source_ioc)
        target_ioc = _canonical_relationship_ioc(target_ioc)
        if source_ioc == target_ioc:
            raise ValueError("an indicator cannot relate to itself")
        if not source_ioc or not target_ioc:
            raise ValueError("relationship endpoints must not be empty")
        if not 0 <= confidence <= 1:
            raise ValueError("relationship confidence must be between 0 and 1")
        relationship_type = relationship_type.strip()
        if not relationship_type:
            raise ValueError("relationship type must not be empty")
        timestamp = _normalize_timestamp(recorded_at) or datetime.now(
            timezone.utc
        ).isoformat()
        requested_valid_from = _normalize_timestamp(valid_from)
        requested_valid_to = _normalize_timestamp(valid_to)
        evidence_source = evidence_source.strip() or "analyst"
        attributes = attributes or {}
        if evidence_observation_id is not None:
            observation = self.conn.execute(
                "SELECT source, observation_json FROM evidence_observations WHERE id = ?",
                (evidence_observation_id,),
            ).fetchone()
            if observation is None:
                raise ValueError("evidence observation was not found")
            if observation["source"] != evidence_source:
                raise ValueError("evidence source does not match the observation")
            evidence = json.loads(observation["observation_json"])
            candidates = [
                item
                for item in evidence.get("related_entities", [])
                if isinstance(item.get("source_ioc"), str)
                and _canonical_relationship_ioc(item["source_ioc"]) == source_ioc
                and isinstance(item.get("target_ioc"), str)
                and _canonical_relationship_ioc(item["target_ioc"]) == target_ioc
                and item.get("relationship_type") == relationship_type
            ]
            support = next(
                (
                    item
                    for item in candidates
                    if (
                        requested_valid_from is None
                        or _normalize_timestamp(
                            item.get("valid_from")
                            or item.get("observed_at")
                            or evidence.get("observed_at")
                            or evidence.get("collected_at")
                        )
                        == requested_valid_from
                    )
                    and (
                        requested_valid_to is None
                        or _normalize_timestamp(item.get("valid_to"))
                        == requested_valid_to
                    )
                    and (
                        not attributes
                        or attributes == item.get("attributes", {})
                    )
                ),
                None,
            )
            if support is None:
                raise ValueError("the observation does not support this relationship")
            for selected_type, supported_type, value, endpoint in (
                (
                    source_entity_type,
                    support.get("source_entity_type"),
                    source_ioc,
                    "source",
                ),
                (
                    target_entity_type,
                    support.get("target_entity_type"),
                    target_ioc,
                    "target",
                ),
                ):
                if selected_type and _entity_type_for(
                    value,
                    explicit=selected_type,
                    relationship_type=relationship_type,
                    endpoint=endpoint,
                ) != _entity_type_for(
                    value,
                    explicit=supported_type,
                    relationship_type=relationship_type,
                    endpoint=endpoint,
                ):
                    raise ValueError("entity type conflicts with supporting observation")
            valid_from = (
                _normalize_timestamp(
                    support.get("valid_from")
                    or support.get("observed_at")
                    or evidence.get("observed_at")
                    or evidence.get("collected_at")
                )
                or timestamp
            )
            valid_to = _normalize_timestamp(support.get("valid_to"))
            if not attributes:
                attributes = support.get("attributes", {})
        else:
            valid_from = requested_valid_from or timestamp
            valid_to = requested_valid_to
        if valid_to and valid_to < valid_from:
            raise ValueError("relationship valid_to must not precede valid_from")
        source_entity_type = _entity_type_for(
            source_ioc,
            explicit=source_entity_type,
            relationship_type=relationship_type,
            endpoint="source",
        )
        target_entity_type = _entity_type_for(
            target_ioc,
            explicit=target_entity_type,
            relationship_type=relationship_type,
            endpoint="target",
        )
        source_entity_id = self._ensure_graph_entity(
            source_ioc,
            source_entity_type,
            attributes if source_entity_type == "certificate" else None,
        )
        target_entity_id = self._ensure_graph_entity(
            target_ioc,
            target_entity_type,
            attributes if target_entity_type == "certificate" else None,
        )
        self.conn.execute(
            """
            INSERT OR IGNORE INTO indicator_relationships(
                source_ioc, target_ioc, relationship_type, confidence,
                evidence_source, created_at, valid_from, valid_to,
                evidence_observation_id, attributes_json,
                source_entity_id, target_entity_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_ioc,
                target_ioc,
                relationship_type,
                confidence,
                evidence_source,
                timestamp,
                valid_from,
                valid_to,
                evidence_observation_id,
                json.dumps(attributes, sort_keys=True),
                source_entity_id,
                target_entity_id,
            ),
        )
        row = self.conn.execute(
            """
            SELECT edge.*, source_entity.entity_type AS source_entity_type,
                   target_entity.entity_type AS target_entity_type
            FROM indicator_relationships AS edge
            LEFT JOIN graph_entities AS source_entity
              ON source_entity.id = edge.source_entity_id
            LEFT JOIN graph_entities AS target_entity
              ON target_entity.id = edge.target_entity_id
            WHERE edge.source_ioc = ? AND edge.target_ioc = ?
              AND edge.relationship_type = ? AND edge.evidence_source = ?
              AND edge.evidence_observation_id IS ?
            ORDER BY edge.id DESC LIMIT 1
            """,
            (
                source_ioc,
                target_ioc,
                relationship_type,
                evidence_source,
                evidence_observation_id,
            ),
        ).fetchone()
        if row is None:
            raise RuntimeError("failed to persist indicator relationship")
        return _relationship_dict(row)

    def relationships(
        self, ioc: str, limit: int = 100, as_of: str | None = None
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        at = _normalize_timestamp(as_of)
        time_filter = (
            " AND edge.created_at <= ? AND edge.valid_from <= ? "
            "AND (edge.valid_to IS NULL OR edge.valid_to >= ?)"
            if at
            else ""
        )
        params: list[Any] = [ioc, ioc]
        if at:
            params.extend([at, at, at])
        params.append(limit)
        with self._lock:
            rows = self.conn.execute(
                f"""
                SELECT edge.*, source_entity.entity_type AS source_entity_type,
                       target_entity.entity_type AS target_entity_type
                FROM indicator_relationships AS edge
                LEFT JOIN graph_entities AS source_entity
                  ON source_entity.id = edge.source_entity_id
                LEFT JOIN graph_entities AS target_entity
                  ON target_entity.id = edge.target_entity_id
                WHERE (edge.source_ioc = ? OR edge.target_ioc = ?){time_filter}
                ORDER BY edge.id DESC LIMIT ?
                """,
                params,
            ).fetchall()
        return [_relationship_dict(row) for row in rows]

    def _graph_root(self, ioc: str, entity_type: str | None = None) -> dict[str, Any]:
        root_type = _entity_type_for(ioc, explicit=entity_type)
        root_value = _canonical_entity_value(ioc, root_type)
        with self._lock:
            root_row = self.conn.execute(
                "SELECT id FROM graph_entities WHERE entity_type = ? "
                "AND canonical_value = ?",
                (root_type, root_value),
            ).fetchone()
        return {
            "entity_id": int(root_row["id"]) if root_row is not None else None,
            "id": ioc,
            "entity_type": root_type,
            "canonical_value": root_value,
            "display_value": ioc,
            "metadata": {},
        }

    def _relationships_for_entities(
        self, entity_ids: list[int], limit: int, as_of: str | None
    ) -> list[dict[str, Any]]:
        unique_ids = sorted(set(entity_ids))
        if not unique_ids or limit < 1:
            return []
        at = _normalize_timestamp(as_of)
        time_filter = (
            " AND edge.created_at <= ? AND edge.valid_from <= ? "
            "AND (edge.valid_to IS NULL OR edge.valid_to >= ?)"
            if at
            else ""
        )
        rows_by_id: dict[int, sqlite3.Row] = {}
        # Keep each query below SQLite's traditional 999-parameter limit: the
        # entity list is bound twice for the two endpoint columns.
        chunk_size = 400
        with self._lock:
            for offset in range(0, len(unique_ids), chunk_size):
                chunk = unique_ids[offset : offset + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                params: list[Any] = [*chunk, *chunk]
                if at:
                    params.extend([at, at, at])
                params.append(limit)
                rows = self.conn.execute(
                    f"""
                    SELECT edge.*, source_entity.entity_type AS source_entity_type,
                           target_entity.entity_type AS target_entity_type
                    FROM indicator_relationships AS edge
                    LEFT JOIN graph_entities AS source_entity
                      ON source_entity.id = edge.source_entity_id
                    LEFT JOIN graph_entities AS target_entity
                      ON target_entity.id = edge.target_entity_id
                    WHERE (edge.source_entity_id IN ({placeholders})
                           OR edge.target_entity_id IN ({placeholders})){time_filter}
                    ORDER BY edge.id DESC LIMIT ?
                    """,
                    params,
                ).fetchall()
                rows_by_id.update({int(row["id"]): row for row in rows})
        return [_relationship_dict(row) for row in rows_by_id.values()]

    def _relationship_graph_for_roots(
        self,
        roots: list[dict[str, Any]],
        limit: int,
        max_depth: int,
        as_of: str | None,
    ) -> dict[str, Any]:
        root_ids = {
            root["entity_id"] for root in roots if root["entity_id"] is not None
        }
        edges_by_id: dict[int, dict[str, Any]] = {}
        if len(root_ids) == 1:
            # Keep single-root graph ranking and truncation behavior unchanged.
            root_id = next(iter(root_ids))
            visited = {root_id}
            single_frontier = [root_id]
            depth = 0
            while (
                single_frontier
                and depth < max_depth
                and len(edges_by_id) < limit
            ):
                single_next_frontier: dict[int, float] = {}
                for current in single_frontier:
                    incident = self._relationships_for_entities(
                        [current], limit - len(edges_by_id), as_of
                    )
                    incident.sort(
                        key=lambda edge: (
                            -float(edge["confidence"]),
                            -int(edge["id"]),
                        )
                    )
                    for edge in incident:
                        edges_by_id.setdefault(edge["id"], edge)
                        other = (
                            edge["target_entity_id"]
                            if edge["source_entity_id"] == current
                            else edge["source_entity_id"]
                        )
                        if other is not None and other not in visited:
                            visited.add(other)
                            single_next_frontier[other] = max(
                                single_next_frontier.get(other, 0.0),
                                float(edge["confidence"]),
                            )
                        if len(edges_by_id) >= limit:
                            break
                    if len(edges_by_id) >= limit:
                        break
                single_frontier = sorted(
                    single_next_frontier,
                    key=lambda node: (-single_next_frontier[node], node),
                )
                depth += 1
        else:
            # Case replay traverses from every indicator together so shared
            # investigation and observation neighborhoods are queried once.
            visited = set(root_ids)
            multi_frontier = {entity_id: 1.0 for entity_id in root_ids}
            depth = 0
            while (
                multi_frontier
                and depth < max_depth
                and len(edges_by_id) < limit
            ):
                incident = self._relationships_for_entities(
                    list(multi_frontier), limit - len(edges_by_id), as_of
                )
                incident.sort(
                    key=lambda edge: (
                        -float(edge["confidence"]),
                        -int(edge["id"]),
                    )
                )
                multi_next_frontier: dict[int, float] = {}
                for edge in incident:
                    edges_by_id.setdefault(edge["id"], edge)
                    endpoints = (edge["source_entity_id"], edge["target_entity_id"])
                    for other in endpoints:
                        if other is None or other in visited:
                            continue
                        visited.add(other)
                        path_confidence = min(
                            multi_frontier[current]
                            for current in endpoints
                            if current in multi_frontier
                        )
                        multi_next_frontier[other] = max(
                            multi_next_frontier.get(other, 0.0),
                            min(path_confidence, float(edge["confidence"])),
                        )
                    if len(edges_by_id) >= limit:
                        break
                multi_frontier = dict(
                    sorted(
                        multi_next_frontier.items(),
                        key=lambda item: (-item[1], item[0]),
                    )
                )
                depth += 1

        edges = sorted(edges_by_id.values(), key=lambda edge: edge["id"])
        endpoint_ids = root_ids | {
            entity_id
            for edge in edges
            for entity_id in (edge["source_entity_id"], edge["target_entity_id"])
            if entity_id is not None
        }
        evidence_ids = {
            edge["evidence_observation_id"]
            for edge in edges
            if edge["evidence_observation_id"] is not None
        }
        with self._lock:
            entity_rows = []
            sorted_endpoint_ids = sorted(endpoint_ids)
            for offset in range(0, len(sorted_endpoint_ids), 400):
                chunk = sorted_endpoint_ids[offset : offset + 400]
                placeholders = ",".join("?" for _ in chunk)
                entity_rows.extend(
                    self.conn.execute(
                        "SELECT * FROM graph_entities WHERE id IN ("
                        + placeholders
                        + ")",
                        chunk,
                    ).fetchall()
                )
            evidence_rows = []
            if evidence_ids:
                placeholders = ",".join("?" for _ in evidence_ids)
                evidence_rows = self.conn.execute(
                    "SELECT id, observation_key, source, collected_at, "
                    "raw_response_sha256 FROM evidence_observations WHERE id IN ("
                    + placeholders
                    + ")",
                    sorted(evidence_ids),
                ).fetchall()
                observation_values = [
                    f"observation:{row['observation_key']}" for row in evidence_rows
                ]
                if observation_values:
                    value_placeholders = ",".join("?" for _ in observation_values)
                    observation_entities = self.conn.execute(
                        "SELECT * FROM graph_entities WHERE entity_type = "
                        "'provider_observation' AND canonical_value IN ("
                        + value_placeholders
                        + ")",
                        observation_values,
                    ).fetchall()
                    entity_rows.extend(observation_entities)
        node_by_id: dict[int, dict[str, Any]] = {}
        for row in entity_rows:
            node = dict(row)
            node["metadata"] = json.loads(node.pop("metadata_json"))
            node["entity_id"] = node.pop("id")
            node["id"] = node["display_value"]
            node_by_id[node["entity_id"]] = node
        observation_entity_ids = {
            node["canonical_value"]: entity_id
            for entity_id, node in node_by_id.items()
            if node["entity_type"] == "provider_observation"
        }
        for row in evidence_rows:
            entity_id = observation_entity_ids.get(
                f"observation:{row['observation_key']}"
            )
            if entity_id is not None:
                node_by_id[entity_id]["linked_edge_evidence"] = {
                    "observation_id": row["id"],
                    "source": row["source"],
                    "collected_at": row["collected_at"],
                    "raw_response_sha256": row["raw_response_sha256"],
                }
        nodes = list(node_by_id.values())
        represented_roots = {
            (node["entity_type"], node["canonical_value"]) for node in nodes
        }
        nodes.extend(
            root
            for root in roots
            if root["entity_id"] is None
            and (root["entity_type"], root["canonical_value"]) not in represented_roots
        )
        nodes.sort(
            key=lambda node: (node["id"], node["entity_type"], node["entity_id"] or 0)
        )
        return {
            "nodes": nodes,
            "edges": edges,
            "max_depth": max_depth,
            "as_of": as_of,
            "truncated": len(edges) >= limit,
        }

    def relationship_graph(
        self,
        ioc: str,
        limit: int = 100,
        max_depth: int = 1,
        as_of: str | None = None,
        entity_type: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        max_depth = max(1, min(max_depth, 5))
        at = _normalize_timestamp(as_of)
        root = self._graph_root(ioc, entity_type)
        return self._relationship_graph_for_roots([root], limit, max_depth, at)

    def suggest_pivots(
        self,
        ioc: str,
        limit: int = 25,
        as_of: str | None = None,
        entity_type: str | None = None,
    ) -> dict[str, Any]:
        """Rank direct, evidence-backed pivots with an explicit heuristic."""
        if not 1 <= limit <= 100:
            raise ValueError("pivot limit must be between 1 and 100")
        at = _normalize_timestamp(as_of) or datetime.now(timezone.utc).isoformat()
        graph = self.relationship_graph(
            ioc, limit=500, max_depth=1, as_of=at, entity_type=entity_type
        )
        nodes_by_id = {node["entity_id"]: node for node in graph["nodes"]}
        candidates: dict[int, dict[str, Any]] = {}
        for edge in graph["edges"]:
            if edge["source_ioc"] == ioc:
                entity_id = edge["target_entity_id"]
                pivot_value = edge["target_ioc"]
            elif edge["target_ioc"] == ioc:
                entity_id = edge["source_entity_id"]
                pivot_value = edge["source_ioc"]
            else:
                continue
            node = nodes_by_id.get(entity_id)
            if node is None:
                continue
            entity_type = node["entity_type"]
            weight = PIVOT_ENTITY_WEIGHTS.get(entity_type)
            if weight is None:
                continue
            confidence = float(edge["confidence"])
            priority_score = round(confidence * weight, 4)
            candidate = candidates.setdefault(
                entity_id,
                {
                    "entity_id": entity_id,
                    "ioc": pivot_value,
                    "entity_type": entity_type,
                    "canonical_value": node["canonical_value"],
                    "priority_score": priority_score,
                    "priority_basis": {
                        "confidence": confidence,
                        "entity_type_weight": weight,
                        "formula": "confidence * entity_type_weight",
                    },
                    "supporting_edges": [],
                },
            )
            if priority_score > candidate["priority_score"]:
                candidate["priority_score"] = priority_score
                candidate["priority_basis"] = {
                    "confidence": confidence,
                    "entity_type_weight": weight,
                    "formula": "confidence * entity_type_weight",
                }
            candidate["supporting_edges"].append(
                {
                    "id": edge["id"],
                    "relationship_type": edge["relationship_type"],
                    "evidence_source": edge["evidence_source"],
                    "evidence_observation_id": edge["evidence_observation_id"],
                    "created_at": edge["created_at"],
                    "valid_from": edge["valid_from"],
                    "valid_to": edge["valid_to"],
                    "confidence": confidence,
                    "attributes": edge["attributes"],
                }
            )
        ranked = sorted(
            candidates.values(),
            key=lambda candidate: (
                -candidate["priority_score"],
                candidate["entity_type"],
                candidate["canonical_value"],
            ),
        )[:limit]
        for candidate in ranked:
            candidate["supporting_edges"].sort(key=lambda edge: edge["id"])
        return {
            "ioc": ioc,
            "as_of": at,
            "methodology": "confidence_x_entity_type_v1",
            "candidates": ranked,
            "budget": {
                "max_depth": 1,
                "edge_limit": 500,
                "edges_considered": len(graph["edges"]),
                "truncated": graph["truncated"],
            },
        }

    def suggest_pivot_paths(
        self,
        ioc: str,
        limit: int = 25,
        max_depth: int = 4,
        as_of: str | None = None,
        entity_type: str | None = None,
    ) -> dict[str, Any]:
        """Rank bounded simple paths to evidence-backed infrastructure pivots."""
        if not 1 <= limit <= 100:
            raise ValueError("pivot limit must be between 1 and 100")
        if not 1 <= max_depth <= 5:
            raise ValueError("pivot path depth must be between 1 and 5")
        at = _normalize_timestamp(as_of) or datetime.now(timezone.utc).isoformat()
        graph = self.relationship_graph(
            ioc, limit=500, max_depth=max_depth, as_of=at, entity_type=entity_type
        )
        nodes = {node["entity_id"]: node for node in graph["nodes"]}
        root_type = _entity_type_for(ioc, explicit=entity_type)
        root_value = _canonical_entity_value(ioc, root_type)
        root = next(
            (
                entity_id
                for entity_id, node in nodes.items()
                if node["entity_type"] == root_type
                and node["canonical_value"] == root_value
            ),
            None,
        )
        adjacency: dict[int, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        for edge in graph["edges"]:
            source_id = edge["source_entity_id"]
            target_id = edge["target_entity_id"]
            if source_id is None or target_id is None:
                continue
            adjacency[source_id].append((target_id, edge))
            adjacency[target_id].append((source_id, edge))
        for links in adjacency.values():
            links.sort(
                key=lambda item: (
                    -float(item[1]["confidence"]),
                    nodes[item[0]]["entity_type"],
                    nodes[item[0]]["canonical_value"],
                    item[1]["id"],
                )
            )

        ranked_by_entity: dict[int, dict[str, Any]] = {}
        route_edge_keys: dict[int, set[tuple[int, ...]]] = defaultdict(set)
        route_summaries: dict[int, list[dict[str, Any]]] = defaultdict(list)
        route_counts: dict[int, int] = defaultdict(int)
        expansions = 0
        budget_truncated = False
        if root is not None:
            stack: list[
                tuple[int, tuple[int, ...], tuple[tuple[int, int, dict[str, Any]], ...]]
            ] = [(root, (root,), ())]
            while stack:
                current, path_nodes, path_edges = stack.pop()
                if len(path_edges) >= max_depth:
                    continue
                for neighbor, edge in reversed(adjacency.get(current, [])):
                    if expansions >= MAX_PIVOT_PATH_EXPANSIONS:
                        budget_truncated = True
                        break
                    expansions += 1
                    if neighbor in path_nodes:
                        continue
                    next_nodes = (*path_nodes, neighbor)
                    next_edges = (*path_edges, (current, neighbor, edge))
                    pivot_node = nodes[neighbor]
                    weight = PIVOT_ENTITY_WEIGHTS.get(pivot_node["entity_type"])
                    if weight is not None:
                        edge_confidence = [
                            float(path_edge[2]["confidence"])
                            for path_edge in next_edges
                        ]
                        confidence_floor = min(edge_confidence)
                        hops = len(next_edges)
                        depth_penalty = 1 / hops
                        priority_score = round(
                            confidence_floor * weight * depth_penalty, 4
                        )
                        path_key = tuple(next_nodes)
                        edge_key = tuple(path_edge[2]["id"] for path_edge in next_edges)
                        previous = ranked_by_entity.get(neighbor)
                        candidate_key = (priority_score, -hops)
                        should_replace = previous is None
                        if previous is not None:
                            previous_key = (
                                previous["priority_score"],
                                -previous["hop_count"],
                            )
                            should_replace = candidate_key > previous_key or (
                                candidate_key == previous_key
                                and path_key < tuple(previous["_path_entity_ids"])
                            )
                        path_description = [
                            {
                                "entity_id": entity_id,
                                "ioc": nodes[entity_id]["display_value"],
                                "entity_type": nodes[entity_id]["entity_type"],
                            }
                            for entity_id in next_nodes
                        ]
                        hops_description = []
                        for from_id, to_id, path_edge in next_edges:
                            hops_description.append(
                                {
                                    "from": nodes[from_id]["display_value"],
                                    "to": nodes[to_id]["display_value"],
                                    "traversal": (
                                        "forward"
                                        if path_edge["source_entity_id"] == from_id
                                        else "reverse"
                                    ),
                                    "source_ioc": path_edge["source_ioc"],
                                    "target_ioc": path_edge["target_ioc"],
                                    "relationship_type": path_edge[
                                        "relationship_type"
                                    ],
                                    "confidence": float(path_edge["confidence"]),
                                    "evidence_source": path_edge["evidence_source"],
                                    "evidence_observation_id": path_edge[
                                        "evidence_observation_id"
                                    ],
                                    "created_at": path_edge["created_at"],
                                    "valid_from": path_edge["valid_from"],
                                    "valid_to": path_edge["valid_to"],
                                    "attributes": path_edge["attributes"],
                                }
                            )
                        if edge_key not in route_edge_keys[neighbor]:
                            route_edge_keys[neighbor].add(edge_key)
                            route_counts[neighbor] += 1
                            route_summaries[neighbor].append(
                                {
                                    "priority_score": priority_score,
                                    "hop_count": hops,
                                    "priority_basis": {
                                        "minimum_edge_confidence": confidence_floor,
                                        "entity_type_weight": weight,
                                        "hop_count": hops,
                                        "depth_penalty": round(depth_penalty, 4),
                                        "formula": (
                                            "minimum_edge_confidence * "
                                            "entity_type_weight / hop_count"
                                        ),
                                    },
                                    "path": path_description,
                                    "hops": hops_description,
                                    "_path_entity_ids": path_key,
                                    "_path_edge_ids": edge_key,
                                }
                            )
                            route_summaries[neighbor].sort(
                                key=lambda route: (
                                    -route["priority_score"],
                                    route["hop_count"],
                                    route["_path_entity_ids"],
                                    route["_path_edge_ids"],
                                )
                            )
                            del route_summaries[neighbor][
                                MAX_PIVOT_ALTERNATIVE_PATHS + 1 :
                            ]
                        if should_replace:
                            ranked_by_entity[neighbor] = {
                                "_entity_id": neighbor,
                                "ioc": pivot_node["display_value"],
                                "entity_type": pivot_node["entity_type"],
                                "canonical_value": pivot_node["canonical_value"],
                                "priority_score": priority_score,
                                "hop_count": hops,
                                "priority_basis": {
                                    "minimum_edge_confidence": confidence_floor,
                                    "entity_type_weight": weight,
                                    "hop_count": hops,
                                    "depth_penalty": round(depth_penalty, 4),
                                    "formula": (
                                        "minimum_edge_confidence * "
                                        "entity_type_weight / hop_count"
                                    ),
                                },
                                "path": path_description,
                                "hops": hops_description,
                                "_path_entity_ids": path_key,
                                "_path_edge_ids": edge_key,
                            }
                    if len(next_edges) < max_depth:
                        stack.append((neighbor, next_nodes, next_edges))
                if budget_truncated:
                    break

        ranked = sorted(
            ranked_by_entity.values(),
            key=lambda candidate: (
                -candidate["priority_score"],
                candidate["hop_count"],
                candidate["entity_type"],
                candidate["canonical_value"],
                candidate["_path_entity_ids"],
            ),
        )[:limit]
        for candidate in ranked:
            entity_id = candidate.pop("_entity_id")
            candidate["supporting_path_count"] = route_counts[entity_id]
            candidate["alternative_paths"] = [
                {
                    key: route[key]
                    for key in (
                        "priority_score",
                        "hop_count",
                        "priority_basis",
                        "path",
                        "hops",
                    )
                }
                for route in route_summaries[entity_id]
                if route["_path_edge_ids"] != candidate["_path_edge_ids"]
            ][:MAX_PIVOT_ALTERNATIVE_PATHS]
            candidate.pop("_path_entity_ids")
            candidate.pop("_path_edge_ids")
        return {
            "ioc": ioc,
            "as_of": at,
            "methodology": "confidence_floor_x_entity_type_over_hops_v1",
            "candidates": ranked,
            "budget": {
                "max_depth": max_depth,
                "edge_limit": 500,
                "max_expansions": MAX_PIVOT_PATH_EXPANSIONS,
                "alternative_path_limit": MAX_PIVOT_ALTERNATIVE_PATHS,
                "expansions": expansions,
                "truncated": bool(
                    graph["truncated"] or budget_truncated
                ),
            },
        }

    def close(self) -> None:
        self.conn.close()
