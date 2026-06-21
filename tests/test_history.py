from ioc_enricher.config import Config
from ioc_enricher.engine import Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult


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
    assert graph["nodes"] == [{"id": "203.0.113.7"}, {"id": "evil.example"}]
    assert graph["edges"][0]["evidence_source"] == "dns"
