import hashlib
import json
import sqlite3

from ioc_enricher.config import Config
from ioc_enricher.engine import Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import score


def test_history_migrates_and_preserves_snapshots(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(
        ioc="example.com", ioc_type=IocType.DOMAIN, verdict="suspicious", score=0.4
    )

    first_id = store.record(result, looked_up_at="2026-01-01T00:00:00+00:00")
    result.score = 0.8
    second_id = store.record(result, looked_up_at="2026-01-02T00:00:00+00:00")

    assert second_id > first_id
    assert [item["score"] for item in store.list_enrichments("example.com")] == [
        0.8,
        0.4,
    ]
    assert store.indicator("example.com") == {
        "ioc": "example.com",
        "ioc_type": "domain",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-02T00:00:00+00:00",
        "tags": [],
        "status": "open",
        "analyst_notes": "",
        "verdict_override": None,
        "override_reason": None,
        "override_at": None,
    }


def test_dashboard_summary_aggregates_verdicts_and_case_states(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(
        EnrichmentResult(
            ioc="evil.example", ioc_type=IocType.DOMAIN, verdict="malicious"
        )
    )
    store.record(
        EnrichmentResult(ioc="clean.example", ioc_type=IocType.DOMAIN, verdict="clean")
    )
    store.create_investigation("Triage")

    summary = store.dashboard_summary()

    assert summary["verdict_counts"] == {"clean": 1, "malicious": 1}
    assert summary["investigation_counts"] == {"open": 1}
    assert summary["recent_enrichments"][0]["ioc"] == "clean.example"


def test_engine_records_completed_enrichment(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), sources=[], history=store)
    engine.connectors = []

    result = engine.enrich("example.com")

    history = store.list_enrichments("example.com")
    assert history[0]["result"]["verdict"] == result.verdict


def test_source_provenance_survives_snapshot_persistence(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    source = SourceResult(
        source="test-provider",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        raw={"answer": ["203.0.113.7"]},
        connector_version="2.1",
        normalization_version="3",
        confidence=0.8,
        freshness={"state": "fresh"},
        extraction_metadata={"field": "answer", "count": 1},
        related_entities=[{"type": "ip", "value": "203.0.113.7"}],
    )
    result.add(source)

    store.record(result, looked_up_at="2026-01-01T00:00:00+00:00")
    saved = store.list_enrichments("example.com")[0]["result"]["sources"][0]

    assert saved["raw_response_sha256"] == source.raw_response_sha256
    assert len(saved["raw_response_sha256"]) == 64
    assert saved["connector_version"] == "2.1"
    assert saved["normalization_version"] == "3"
    assert saved["confidence"] == 0.8
    assert saved["freshness"] == {"state": "fresh"}
    assert saved["extraction_metadata"] == {"field": "answer", "count": 1}
    assert saved["related_entities"] == [
        {"type": "ip", "value": "203.0.113.7"}
    ]


def test_evidence_observations_have_stable_ids_and_are_immutable(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    first_source = SourceResult(
        source="passive-dns",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        found=True,
        raw={"answer": "203.0.113.7"},
        collected_at="2026-01-01T00:00:00+00:00",
    )
    first = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    first.add(first_source)
    first_enrichment_id = store.record(first)

    repeated = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    repeated.add(first_source)
    repeated_enrichment_id = store.record(repeated)

    original = store.observations_for_enrichment(first_enrichment_id)[0]
    same_evidence = store.observations_for_enrichment(repeated_enrichment_id)[0]
    first_source.raw["answer"] = "198.51.100.4"
    still_original = store.observations_for_enrichment(first_enrichment_id)[0]

    assert original["id"] == same_evidence["id"]
    assert original["observation_key"] == same_evidence["observation_key"]
    assert still_original["observation"]["raw"] == {"answer": "203.0.113.7"}


def test_changed_provider_observation_gets_a_new_evidence_id(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    results = []
    for address, collected_at in [
        ("203.0.113.7", "2026-01-01T00:00:00+00:00"),
        ("198.51.100.4", "2026-01-02T00:00:00+00:00"),
    ]:
        result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
        result.add(
            SourceResult(
                source="passive-dns",
                ioc="example.com",
                ioc_type=IocType.DOMAIN,
                found=True,
                raw={"answer": address},
                collected_at=collected_at,
            )
        )
        results.append(store.record(result))

    first = store.observations_for_enrichment(results[0])[0]
    second = store.observations_for_enrichment(results[1])[0]

    assert first["id"] != second["id"]
    assert first["observation"]["raw"] != second["observation"]["raw"]


def test_repeated_observation_keeps_each_snapshot_position(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    source = SourceResult(
        source="passive-dns",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        found=True,
        raw={"answer": "203.0.113.7"},
        collected_at="2026-01-01T00:00:00+00:00",
    )
    result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    result.add(source)
    result.add(source)

    enrichment_id = store.record(result)
    observations = store.observations_for_enrichment(enrichment_id)

    assert [row["ordinal"] for row in observations] == [0, 1]
    assert observations[0]["id"] == observations[1]["id"]


def test_migration_backfills_observations_from_existing_snapshots(tmp_path):
    path = tmp_path / "legacy-history.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
    conn.executemany(
        "INSERT INTO schema_migrations(version) VALUES (?)",
        [(version,) for version in range(1, 6)],
    )
    conn.execute(
        "CREATE TABLE enrichments ("
        "id INTEGER PRIMARY KEY, ioc TEXT, ioc_type TEXT, verdict TEXT, score REAL, "
        "confidence TEXT, looked_up_at TEXT, result_json TEXT)"
    )
    conn.execute(
        "CREATE TABLE indicator_relationships ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, source_ioc TEXT NOT NULL, "
        "target_ioc TEXT NOT NULL, relationship_type TEXT NOT NULL, "
        "confidence REAL NOT NULL DEFAULT 1.0, "
        "evidence_source TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL, "
        "UNIQUE(source_ioc, target_ioc, relationship_type, evidence_source))"
    )
    conn.execute(
        "INSERT INTO indicator_relationships(source_ioc, target_ioc, "
        "relationship_type, confidence, evidence_source, created_at) "
        "VALUES ('old.example', '203.0.113.9', 'resolves_to', 0.7, 'dns', "
        "'2025-01-01T00:00:00+00:00')"
    )
    raw = {"answer": "203.0.113.7"}
    legacy_result = {
        "sources": [
            {
                "source": "passive-dns",
                "ioc": "example.com",
                "ioc_type": "domain",
                "found": True,
                "malicious": None,
                "score": None,
                "raw": raw,
                "error": None,
                "tags": [],
                "observed_at": None,
            }
        ]
    }
    conn.execute(
        "INSERT INTO enrichments VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            1,
            "example.com",
            "domain",
            "unknown",
            0.0,
            "low",
            "2026-01-01T00:00:00+00:00",
            json.dumps(legacy_result),
        ),
    )
    conn.commit()
    conn.close()

    store = HistoryStore(path)
    evidence = store.observations_for_enrichment(1)[0]["observation"]
    canonical_raw = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()

    assert evidence["collected_at"] == "2026-01-01T00:00:00+00:00"
    assert evidence["raw_response_sha256"] == hashlib.sha256(canonical_raw).hexdigest()
    migrated_edge = store.relationships("old.example")[0]
    assert migrated_edge["valid_from"] == "2025-01-01T00:00:00+00:00"
    assert migrated_edge["evidence_observation_id"] is None
    assert migrated_edge["source_entity_type"] == "domain"
    assert migrated_edge["target_entity_type"] == "ip"


def test_replay_reproduces_historical_score_from_pinned_time_and_config(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    result.add(
        SourceResult(
            source="virustotal",
            ioc="example.com",
            ioc_type=IocType.DOMAIN,
            found=True,
            malicious=True,
            score=0.8,
            raw={"last_seen": "2020-01-01T00:00:00+00:00"},
            observed_at="2020-01-01T00:00:00+00:00",
        )
    )
    score(
        result,
        settings={
            "weights": {"virustotal": 0.7},
            "thresholds": {"suspicious": 0.3, "malicious": 0.7},
        },
        as_of="2020-01-15T00:00:00+00:00",
    )
    enrichment_id = store.record(result, looked_up_at="2026-01-01T00:00:00+00:00")

    replay = store.replay_enrichment(enrichment_id)

    assert replay is not None
    assert replay["replayable"] is True
    assert replay["matches_original"] is True
    assert replay["replayed"]["decision_trace"]["evaluated_at"] == (
        "2020-01-15T00:00:00+00:00"
    )
    assert replay["replayed"]["decision_trace"]["observations"][0][
        "observation_id"
    ] == replay["observations"][0]["id"]


def test_replay_reports_legacy_snapshots_as_not_replayable(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(
        ioc="legacy.example", ioc_type=IocType.DOMAIN, verdict="clean"
    )
    enrichment_id = store.record(result)

    replay = store.replay_enrichment(enrichment_id)

    assert replay is not None
    assert replay["replayable"] is False
    assert replay["reason"] == "scoring_inputs_missing"


def test_compare_enrichments_explains_new_evidence_and_temporal_graph(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    baseline = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    baseline.add(SourceResult(source="rdap", ioc="example.com", ioc_type=IocType.DOMAIN, collected_at="2026-01-01T00:00:00+00:00", raw={"registrar": "Example"}))
    baseline_id = store.record(baseline, "2026-01-01T00:00:00+00:00")

    updated = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    updated.add(baseline.sources[0])
    updated.add(SourceResult(
        source="passive_dns", ioc="example.com", ioc_type=IocType.DOMAIN,
        found=True, malicious=True, score=0.9, raw={"answer": "192.0.2.7"},
        collected_at="2026-01-02T00:00:00+00:00",
        related_entities=[{"source_ioc": "example.com", "target_ioc": "192.0.2.7", "relationship_type": "resolves_to", "confidence": 0.9, "observed_at": "2026-01-02T00:00:00+00:00"}],
    ))
    score(updated, as_of="2026-01-02T00:00:00+00:00")
    comparison_id = store.record(updated, "2026-01-02T00:00:00+00:00")

    comparison = store.compare_enrichments(baseline_id, comparison_id)

    assert comparison is not None
    assert comparison["verdict_changed"] is True
    assert comparison["evidence"]["added"][0]["observation"]["source"] == "passive_dns"
    assert comparison["evidence"]["added"][0]["decision_contribution"] is not None
    assert [edge["target_ioc"] for edge in comparison["graph"]["added_edges"]] == ["192.0.2.7"]
    assert comparison["graph"]["added_edges"][0]["created_at"] == "2026-01-02T00:00:00+00:00"


def test_compare_enrichments_rejects_different_indicators_and_time_order(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    first = store.record(EnrichmentResult(ioc="one.example", ioc_type=IocType.DOMAIN), "2026-01-02T00:00:00+00:00")
    different_ioc = store.record(EnrichmentResult(ioc="two.example", ioc_type=IocType.DOMAIN), "2026-01-03T00:00:00+00:00")
    earlier = store.record(EnrichmentResult(ioc="one.example", ioc_type=IocType.DOMAIN), "2026-01-01T00:00:00+00:00")
    try:
        store.compare_enrichments(first, different_ioc)
    except ValueError as error:
        assert "same IOC" in str(error)
    else:
        raise AssertionError("cross-IOC comparison must fail")
    try:
        store.compare_enrichments(first, earlier)
    except ValueError as error:
        assert "precede" in str(error)
    else:
        raise AssertionError("reverse-time comparison must fail")


def test_history_updates_analyst_fields_and_records_an_event(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN))

    indicator = store.update_indicator(
        "example.com",
        tags=["Phishing", "phishing", "urgent"],
        status="triaged",
        analyst_notes="Validated against proxy telemetry.",
    )

    assert indicator["tags"] == ["phishing", "urgent"]
    assert indicator["status"] == "triaged"
    assert indicator["analyst_notes"] == "Validated against proxy telemetry."
    assert store.indicator_events("example.com")[0]["data"]["status"] == "triaged"


def test_verdict_override_requires_reason_and_is_audited(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN))

    try:
        store.set_verdict_override("evil.example", "malicious", " ")
    except ValueError as error:
        assert "reason" in str(error)
    else:
        raise AssertionError("an override must require a reason")

    overridden = store.set_verdict_override(
        "evil.example", "malicious", "EDR confirmation"
    )
    cleared = store.clear_verdict_override("evil.example")

    assert overridden is not None
    assert overridden["verdict_override"] == "malicious"
    assert cleared is not None
    assert cleared["verdict_override"] is None
    assert [
        event["event_type"] for event in store.indicator_events("evil.example")[:2]
    ] == ["verdict_override_cleared", "verdict_override_set"]


def test_investigation_groups_indicators_and_preserves_events(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    investigation = store.create_investigation("Credential phishing", "Initial triage")

    updated = store.add_investigation_indicator(investigation["id"], "evil.example")
    store.add_investigation_indicator(investigation["id"], "evil.example")

    assert updated["indicators"] == ["evil.example"]
    assert [
        event["event_type"] for event in store.investigation_events(investigation["id"])
    ] == [
        "indicator_added",
        "investigation_created",
    ]


def test_investigation_lifecycle_update_is_audited(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    investigation = store.create_investigation("Credential phishing")

    updated = store.update_investigation(
        investigation["id"], description="Contained", status="closed"
    )

    assert updated is not None
    assert updated["status"] == "closed"
    assert updated["description"] == "Contained"
    event = store.investigation_events(investigation["id"])[0]
    assert event["event_type"] == "investigation_updated"
    assert event["data"] == {"description": "Contained", "status": "closed"}


def test_event_chains_verify_and_sqlite_guards_reject_edits(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN))
    store.update_indicator("evil.example", status="triaged")
    investigation = store.create_investigation("Triage")
    store.add_investigation_indicator(investigation["id"], "evil.example")

    indicator_events = store.indicator_events("evil.example")
    case_events = store.investigation_events(investigation["id"])
    assert indicator_events[0]["event_hash"]
    assert indicator_events[0]["previous_hash"] == "0" * 64
    assert case_events[0]["previous_hash"] == case_events[1]["event_hash"]
    assert case_events[1]["previous_hash"] == "0" * 64
    assert store.verify_indicator_event_chain("evil.example")["valid"] is True
    assert store.verify_investigation_event_chain(investigation["id"])["valid"] is True

    try:
        store.conn.execute("DELETE FROM indicator_events WHERE id = ?", (indicator_events[0]["id"],))
    except sqlite3.IntegrityError as error:
        assert "append-only" in str(error)
    else:
        raise AssertionError("SQLite guards must reject event deletion")

    store.conn.execute("DROP TRIGGER indicator_events_no_update")
    store.conn.execute(
        "UPDATE indicator_events SET data_json = ? WHERE id = ?",
        ('{"status":"closed"}', indicator_events[0]["id"]),
    )
    store.conn.commit()
    integrity = store.verify_indicator_event_chain("evil.example")
    assert integrity["valid"] is False
    assert integrity["first_invalid_event_id"] == indicator_events[0]["id"]


def test_event_chain_migration_backfills_preexisting_events(tmp_path):
    path = tmp_path / "history.db"
    store = HistoryStore(path)
    store.record(EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN))
    store.update_indicator("example.com", status="triaged")
    investigation = store.create_investigation("Case")
    store.add_investigation_indicator(investigation["id"], "example.com")
    store.conn.executescript(
        """
        DROP TRIGGER indicator_events_no_update;
        DROP TRIGGER indicator_events_no_delete;
        DROP TRIGGER investigation_events_no_update;
        DROP TRIGGER investigation_events_no_delete;
        ALTER TABLE indicator_events DROP COLUMN previous_hash;
        ALTER TABLE indicator_events DROP COLUMN event_hash;
        ALTER TABLE investigation_events DROP COLUMN previous_hash;
        ALTER TABLE investigation_events DROP COLUMN event_hash;
        DELETE FROM schema_migrations WHERE version = 9;
        """
    )
    store.conn.commit()
    store.conn.close()

    migrated = HistoryStore(path)

    assert migrated.verify_indicator_event_chain("example.com")["valid"] is True
    assert migrated.verify_indicator_event_chain("example.com")["checked_events"] == 1
    assert migrated.verify_investigation_event_chain(investigation["id"])["valid"] is True
    assert migrated.verify_investigation_event_chain(investigation["id"])["checked_events"] == 2


def test_relationship_graph_returns_nodes_and_evidence(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    relationship = store.add_relationship(
        "evil.example",
        "203.0.113.7",
        "resolves_to",
        confidence=0.8,
        evidence_source="dns",
    )

    graph = store.relationship_graph("evil.example")

    assert relationship["relationship_type"] == "resolves_to"
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes["203.0.113.7"]["entity_type"] == "ip"
    assert nodes["evil.example"]["entity_type"] == "domain"
    assert relationship["source_entity_type"] == "domain"
    assert relationship["target_entity_type"] == "ip"
    assert graph["edges"][0]["evidence_source"] == "dns"
    assert graph["edges"][0]["valid_from"] == relationship["valid_from"]
    assert graph["edges"][0]["attributes"] == {}


def test_typed_graph_nodes_support_certificate_and_investigation_pivots(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    certificate = store.add_relationship(
        "evil.example",
        "certificate:crtsh:123",
        "has_certificate",
        target_entity_type="certificate",
    )
    store.add_relationship(
        "certificate:crtsh:123",
        "cdn.example.net",
        "certificate_name",
        source_entity_type="certificate",
        target_entity_type="hostname",
    )
    investigation = store.create_investigation("Infrastructure review")
    store.add_investigation_indicator(investigation["id"], "evil.example")

    graph = store.relationship_graph("evil.example", max_depth=3)
    nodes = {node["id"]: node for node in graph["nodes"]}

    assert certificate["target_entity_type"] == "certificate"
    assert nodes["certificate:crtsh:123"]["entity_type"] == "certificate"
    assert nodes["cdn.example.net"]["entity_type"] == "hostname"
    assert nodes[f"investigation:{investigation['id']}"]["entity_type"] == (
        "investigation"
    )
    assert "part_of_investigation" in {
        edge["relationship_type"] for edge in graph["edges"]
    }


def test_graph_traversal_keeps_same_value_entity_types_separate(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.add_relationship(
        "root.example",
        "shared.example",
        "certificate_name",
        target_entity_type="hostname",
    )
    store.add_relationship(
        "shared.example",
        "other.example",
        "domain_related",
        source_entity_type="domain",
        target_entity_type="domain",
    )

    graph = store.relationship_graph("root.example", max_depth=3)
    shared_hostname_graph = store.relationship_graph(
        "shared.example", max_depth=1, entity_type="hostname"
    )
    shared_domain_graph = store.relationship_graph(
        "shared.example", max_depth=1, entity_type="domain"
    )

    assert "other.example" not in {node["id"] for node in graph["nodes"]}
    assert {node["id"] for node in shared_hostname_graph["nodes"]} == {
        "shared.example",
        "root.example",
    }
    assert {node["id"] for node in shared_domain_graph["nodes"]} == {
        "shared.example",
        "other.example",
    }


def test_relationship_rejects_unknown_explicit_entity_type(tmp_path):
    store = HistoryStore(tmp_path / "history.db")

    try:
        store.add_relationship(
            "evil.example",
            "203.0.113.7",
            "resolves_to",
            target_entity_type="made_up_type",
        )
    except ValueError as error:
        assert "entity type" in str(error)
    else:
        raise AssertionError("unsupported graph entity types must be rejected")


def test_pivot_suggestions_rank_typed_nodes_with_provenance_and_time_bounds(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.add_relationship(
        "evil.example",
        "203.0.113.7",
        "resolves_to",
        confidence=0.7,
        evidence_source="passive_dns",
        recorded_at="2025-12-01T00:00:00+00:00",
        valid_from="2025-01-01T00:00:00+00:00",
        valid_to="2030-01-01T00:00:00+00:00",
    )
    store.add_relationship(
        "evil.example",
        "certificate:crtsh:123",
        "has_certificate",
        confidence=0.8,
        target_entity_type="certificate",
        recorded_at="2025-12-01T00:00:00+00:00",
        valid_from="2025-01-01T00:00:00+00:00",
        valid_to="2030-01-01T00:00:00+00:00",
    )
    store.add_relationship(
        "evil.example",
        "expired.example",
        "cname_to",
        confidence=1.0,
        recorded_at="2020-01-01T00:00:00+00:00",
        valid_from="2020-01-01T00:00:00+00:00",
        valid_to="2021-01-01T00:00:00+00:00",
    )

    result = store.suggest_pivots("evil.example", as_of="2026-01-01T00:00:00+00:00")

    assert result["methodology"] == "confidence_x_entity_type_v1"
    assert [item["entity_type"] for item in result["candidates"]] == [
        "certificate",
        "ip",
    ]
    assert result["candidates"][0]["priority_score"] == 0.8
    assert result["candidates"][1]["supporting_edges"][0]["evidence_source"] == (
        "passive_dns"
    )
    assert result["budget"]["max_depth"] == 1


def test_provider_relationships_link_to_observations_and_pivots(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    result.add(
        SourceResult(
            source="passive_dns",
            ioc="example.com",
            ioc_type=IocType.DOMAIN,
            found=True,
            raw={"records": []},
            collected_at="2026-01-10T00:00:00+00:00",
            related_entities=[
                {
                    "source_ioc": "example.com",
                    "target_ioc": "203.0.113.7",
                    "relationship_type": "resolves_to",
                    "valid_from": "2025-12-01T00:00:00+00:00",
                    "valid_to": "2026-01-09T00:00:00+00:00",
                    "attributes": {"record_type": "A"},
                }
            ],
        )
    )
    enrichment_id = store.record(result)
    observation_id = store.observations_for_enrichment(enrichment_id)[0]["id"]
    edge = store.relationships("example.com")[0]

    assert edge["evidence_source"] == "passive_dns"
    assert edge["evidence_observation_id"] == observation_id
    assert edge["valid_from"] == "2025-12-01T00:00:00+00:00"
    assert edge["valid_to"] == "2026-01-09T00:00:00+00:00"
    assert edge["attributes"] == {"record_type": "A"}
    graph = store.relationship_graph("example.com")
    assert any(
        node["entity_type"] == "provider_observation"
        and node["linked_edge_evidence"]["observation_id"] == observation_id
        for node in graph["nodes"]
    )
    try:
        store.add_relationship(
            "example.com",
            "198.51.100.5",
            "resolves_to",
            evidence_source="passive_dns",
            evidence_observation_id=observation_id,
        )
    except ValueError as error:
        assert "does not support" in str(error)
    else:
        raise AssertionError("unobserved relationships must not cite evidence")


def test_bad_edge_metadata_does_not_drop_provider_observation(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    result.add(
        SourceResult(
            source="passive_dns",
            ioc="example.com",
            ioc_type=IocType.DOMAIN,
            found=True,
            raw={"record_count": 1},
            related_entities=[
                {
                    "source_ioc": "example.com",
                    "target_ioc": "203.0.113.7",
                    "relationship_type": "resolves_to",
                    "valid_from": "not-a-timestamp",
                }
            ],
        )
    )

    enrichment_id = store.record(result)

    assert store.observations_for_enrichment(enrichment_id)
    assert store.relationships("example.com") == []


def test_relationship_graph_traverses_with_temporal_and_depth_budgets(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.add_relationship(
        "root.example",
        "203.0.113.7",
        "resolves_to",
        valid_from="2020-01-01T00:00:00+00:00",
        valid_to="2100-01-01T00:00:00+00:00",
    )
    store.add_relationship(
        "203.0.113.7",
        "sha256:abc",
        "hosted_payload",
        valid_from="2020-01-01T00:00:00+00:00",
    )
    store.add_relationship(
        "root.example",
        "old.example",
        "cname_to",
        valid_from="2020-01-01T00:00:00+00:00",
        valid_to="2025-01-01T00:00:00+00:00",
    )

    shallow = store.relationship_graph(
        "root.example", max_depth=1, as_of="2099-01-01T00:00:00+00:00"
    )
    deep = store.relationship_graph(
        "root.example", max_depth=3, as_of="2099-01-01T00:00:00+00:00"
    )

    assert {node["id"] for node in shallow["nodes"]} == {
        "root.example",
        "203.0.113.7",
    }
    assert {node["id"] for node in deep["nodes"]} == {
        "root.example",
        "203.0.113.7",
        "sha256:abc",
    }
    assert deep["max_depth"] == 3
    assert deep["as_of"] == "2099-01-01T00:00:00+00:00"
