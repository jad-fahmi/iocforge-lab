from ioc_enricher.config import Config
from ioc_enricher.engine import Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult


def test_history_migrates_and_preserves_snapshots(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(
        ioc="example.com", ioc_type=IocType.DOMAIN, verdict="suspicious", score=0.4
    )

    first_id = store.record(result, looked_up_at="2026-01-01T00:00:00+00:00")
    result.score = 0.8
    second_id = store.record(result, looked_up_at="2026-01-02T00:00:00+00:00")

    assert second_id > first_id
    assert [item["score"] for item in store.list_enrichments("example.com")] == [0.8, 0.4]
    assert store.indicator("example.com") == {
        "ioc": "example.com",
        "ioc_type": "domain",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-02T00:00:00+00:00",
        "tags": [],
        "status": "open",
        "analyst_notes": "",
    }


def test_engine_records_completed_enrichment(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), sources=[], history=store)
    engine.connectors = []

    result = engine.enrich("example.com")

    history = store.list_enrichments("example.com")
    assert history[0]["result"]["verdict"] == result.verdict


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
