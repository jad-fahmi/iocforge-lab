from pathlib import Path

from fastapi.testclient import TestClient
from ioc_enricher.api import app as api_module
from ioc_enricher.api.rate_limit import RateLimiter
from ioc_enricher.bundles import inspect_bundle
from ioc_enricher.config import Config
from ioc_enricher.engine import Engine
from ioc_enricher.evaluation import load_fixture
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult


def _client(monkeypatch):
    engine = Engine(Config())
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    return TestClient(api_module.app)


def test_analyst_workbench_serves_the_api_backed_shell(monkeypatch):
    response = _client(monkeypatch).get("/")

    assert response.status_code == 200
    assert "IOCForge Analyst Workbench" in response.text
    assert "Evidence-backed relationships" in response.text
    assert "Create investigation" in response.text
    assert "Add to investigation" in response.text
    assert "Decision trace and scoring inputs" in response.text
    assert "Compare snapshots" in response.text
    assert "Event chain:" in response.text
    assert "Download reproducible .iocforge bundle" in response.text
    assert "Validate and replay offline" in response.text
    assert "/pivots?limit=25" in response.text
    assert "const API = '/api/v1'" in response.text
    assert "p.available" in response.text
    assert "p.healthy" not in response.text


def test_versioned_enrich_endpoint_returns_typed_payload(monkeypatch):
    response = _client(monkeypatch).post("/api/v1/enrich", json={"ioc": "example.com"})

    assert response.status_code == 200
    assert response.json()["ioc_type"] == "domain"
    assert response.json()["sources"] == []


def test_api_rate_limit_returns_retry_headers(monkeypatch):
    monkeypatch.setattr(
        api_module, "rate_limiter", RateLimiter(limit=1, window_seconds=60)
    )
    client = _client(monkeypatch)

    first = client.get("/api/v1/providers")
    second = client.get("/api/v1/providers")

    assert first.headers["X-RateLimit-Remaining"] == "0"
    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "rate_limit_exceeded"
    assert second.headers["Retry-After"] == "60"


def test_score_explanation_endpoint_returns_only_scoring_decision(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/score/explain", json={"ioc": "example.com"}
    )

    assert response.status_code == 200
    assert response.json()["verdict"] == "clean"
    assert "sources" not in response.json()
    assert "recommended_action" in response.json()
    assert response.json()["scoring_config"]["thresholds"]["malicious"] == 0.6
    assert response.json()["decision_trace"]["methodology_version"] == "2"


def test_batch_endpoint_deduplicates_iocs(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/enrich/batch", json={"iocs": ["example.com", "example.com"]}
    )

    assert response.status_code == 200
    assert len(response.json()["results"]) == 1


def test_extract_endpoint_and_validation(monkeypatch):
    client = _client(monkeypatch)

    extracted = client.post("/api/v1/extract", json={"text": "alert evil[.]com"})
    invalid = client.post("/api/v1/enrich", json={"ioc": ""})

    assert extracted.json()["indicators"][0]["normalized"] == "evil.com"
    assert invalid.status_code == 422


def test_stix_export_endpoint_returns_a_stix_21_bundle(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/interoperability/stix/export", json={"iocs": ["example.com"]}
    )

    assert response.status_code == 200
    assert response.json()["type"] == "bundle"
    assert response.json()["objects"][0]["pattern_type"] == "stix"


def test_stix_import_endpoint_extracts_validated_indicators(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/interoperability/stix/import",
        json={
            "bundle": {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "pattern": "[ipv4-addr:value = '198.51.100.9']",
                    }
                ],
            }
        },
    )

    assert response.status_code == 200
    assert response.json()["indicators"][0]["ioc_type"] == "ipv4"


def test_misp_export_endpoint_returns_unpublished_event(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/interoperability/misp/export",
        json={"iocs": ["example.com"], "info": "Case export"},
    )

    assert response.status_code == 200
    assert response.json()["Event"]["published"] is False
    assert response.json()["Event"]["Attribute"][0]["type"] == "domain"


def test_misp_import_endpoint_extracts_validated_attributes(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/interoperability/misp/import",
        json={
            "event": {
                "Event": {
                    "Attribute": [{"type": "url", "value": "https://evil.example/path"}]
                }
            }
        },
    )

    assert response.status_code == 200
    assert response.json()["indicators"][0]["ioc_type"] == "url"


def test_history_endpoint_filters_and_paginates(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(
        EnrichmentResult(
            ioc="example.com", ioc_type=IocType.DOMAIN, verdict="clean", score=0.0
        ),
        looked_up_at="2026-01-01T00:00:00+00:00",
    )
    store.record(
        EnrichmentResult(
            ioc="other.example", ioc_type=IocType.DOMAIN, verdict="low", score=0.1
        ),
        looked_up_at="2026-01-02T00:00:00+00:00",
    )
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).get(
        "/api/v1/history", params={"ioc": "example.com", "limit": 1}
    )

    assert response.status_code == 200
    assert response.json()["items"][0]["ioc"] == "example.com"
    assert response.json()["limit"] == 1


def test_history_replay_endpoint_reconstructs_saved_decision(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    engine.enrich("example.com")
    enrichment_id = store.list_enrichments("example.com")[0]["id"]
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).get(
        f"/api/v1/history/{enrichment_id}/replay"
    )

    assert response.status_code == 200
    assert response.json()["replayable"] is True
    assert response.json()["matches_original"] is True


def test_history_replay_endpoint_returns_not_found_for_unknown_id(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).get("/api/v1/history/999999/replay")

    assert response.status_code == 404


def test_history_compare_endpoint_returns_snapshot_diff(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    baseline = store.record(EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN), "2026-01-01T00:00:00+00:00")
    comparison = store.record(EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN), "2026-01-02T00:00:00+00:00")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).get(f"/api/v1/history/{baseline}/compare/{comparison}")

    assert response.status_code == 200
    assert response.json()["baseline"]["enrichment_id"] == baseline
    assert response.json()["comparison"]["enrichment_id"] == comparison


def test_investigation_integrity_endpoint_checks_event_chain(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    investigation = store.create_investigation("Triage case")
    store.add_investigation_indicator(investigation["id"], "evil.example")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).get(
        f"/api/v1/investigations/{investigation['id']}/integrity"
    )

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["checked_events"] == 2


def test_investigation_bundle_api_exports_and_loads_offline(
    monkeypatch, tmp_path
):
    store = HistoryStore(tmp_path / "history.db")
    investigation = store.create_investigation("Bundle case")
    store.add_investigation_indicator(investigation["id"], "evil.example")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)

    exported = client.get(
        f"/api/v1/investigations/{investigation['id']}/bundle"
    )
    loaded = client.post(
        "/api/v1/investigations/bundles/inspect",
        content=exported.content,
        headers={"content-type": "application/zip"},
    )

    assert exported.status_code == 200
    assert exported.headers["content-disposition"].endswith(".iocforge\"")
    assert inspect_bundle(exported.content)["investigation"]["title"] == "Bundle case"
    assert loaded.status_code == 200
    assert loaded.json()["event_integrity"]["investigation"]["valid"] is True


def test_provider_evaluation_api_runs_an_offline_fixture():
    fixture = load_fixture(
        Path(__file__).parent / "fixtures" / "provider-evaluation-v1.json"
    )

    response = TestClient(api_module.app).post("/api/v1/evaluation/run", json=fixture)

    assert response.status_code == 200
    assert response.json()["methodology"] == "iocforge-provider-evaluation-v1"
    assert response.json()["providers"]["alpha"]["coverage"] == 0.75


def test_dashboard_endpoint_exposes_provider_and_persisted_metrics(
    monkeypatch, tmp_path
):
    store = HistoryStore(tmp_path / "history.db")
    store.record(
        EnrichmentResult(
            ioc="evil.example", ioc_type=IocType.DOMAIN, verdict="malicious"
        )
    )
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).get("/api/v1/dashboard")

    assert response.status_code == 200
    assert response.json()["verdict_counts"] == {"malicious": 1}
    assert "providers" in response.json()


def test_indicator_metadata_endpoints(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN))
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)

    updated = client.patch(
        "/api/v1/indicators/example.com",
        json={"tags": ["phishing"], "status": "triaged", "analyst_notes": "reviewed"},
    )
    events = client.get("/api/v1/indicators/example.com/events")

    assert updated.status_code == 200
    assert updated.json()["tags"] == ["phishing"]
    assert events.json()[0]["event_type"] == "indicator_updated"


def test_verdict_override_endpoint_requires_reason_and_can_be_cleared(
    monkeypatch, tmp_path
):
    store = HistoryStore(tmp_path / "history.db")
    store.record(EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN))
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)

    invalid = client.put(
        "/api/v1/indicators/evil.example/verdict-override",
        json={"verdict": "malicious", "reason": ""},
    )
    set_override = client.put(
        "/api/v1/indicators/evil.example/verdict-override",
        json={"verdict": "malicious", "reason": "EDR confirmation"},
    )
    cleared = client.delete("/api/v1/indicators/evil.example/verdict-override")

    assert invalid.status_code == 422
    assert set_override.json()["verdict_override"] == "malicious"
    assert cleared.json()["verdict_override"] is None


def test_investigation_endpoints_group_indicators(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)

    created = client.post(
        "/api/v1/investigations",
        json={"title": "Malware triage", "description": "Review"},
    )
    investigation_id = created.json()["id"]
    updated = client.post(
        f"/api/v1/investigations/{investigation_id}/indicators",
        json={"ioc": "evil.example"},
    )

    assert created.status_code == 201
    assert updated.json()["indicators"] == ["evil.example"]
    assert (
        client.get(f"/api/v1/investigations/{investigation_id}/events").status_code
        == 200
    )


def test_investigation_endpoint_updates_lifecycle(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)
    created = client.post("/api/v1/investigations", json={"title": "Case"})

    response = client.patch(
        f"/api/v1/investigations/{created.json()['id']}",
        json={"description": "Remediated", "status": "closed"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "closed"
    assert response.json()["description"] == "Remediated"


def test_investigation_report_endpoint_returns_markdown(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    store.record(EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN))
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)
    investigation = client.post("/api/v1/investigations", json={"title": "Report case"})
    investigation_id = investigation.json()["id"]
    client.post(
        f"/api/v1/investigations/{investigation_id}/indicators",
        json={"ioc": "evil.example"},
    )

    response = client.get(f"/api/v1/investigations/{investigation_id}/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "# Investigation: Report case" in response.text


def test_relationship_endpoints_return_graph_data(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    client = TestClient(api_module.app)

    created = client.post(
        "/api/v1/relationships",
        json={
            "source_ioc": "evil.example",
            "target_ioc": "203.0.113.7",
            "relationship_type": "resolves_to",
            "confidence": 0.8,
            "evidence_source": "dns",
        },
    )
    graph = client.get("/api/v1/indicators/evil.example/graph")

    assert created.status_code == 201
    assert graph.json()["edges"][0]["target_ioc"] == "203.0.113.7"
    assert graph.json()["max_depth"] == 1
    pivots = client.get(
        "/api/v1/indicators/evil.example/pivots",
        params={"as_of": "2099-01-01T00:00:00+00:00"},
    )
    assert pivots.status_code == 200
    assert pivots.json()["candidates"][0]["entity_type"] == "ip"
    invalid_time = client.get(
        "/api/v1/indicators/evil.example/graph", params={"as_of": "not-a-date"}
    )
    assert invalid_time.status_code == 422


def test_relationship_api_accepts_matching_observation_provenance(monkeypatch, tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    result.add(
        SourceResult(
            source="passive_dns",
            ioc="example.com",
            ioc_type=IocType.DOMAIN,
            found=True,
            related_entities=[
                {
                    "source_ioc": "example.com",
                    "target_ioc": "203.0.113.7",
                    "relationship_type": "resolves_to",
                }
            ],
        )
    )
    enrichment_id = store.record(result)
    observation_id = store.observations_for_enrichment(enrichment_id)[0]["id"]
    engine = Engine(Config(), history=store)
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)

    response = TestClient(api_module.app).post(
        "/api/v1/relationships",
        json={
            "source_ioc": "example.com",
            "target_ioc": "203.0.113.7",
            "relationship_type": "resolves_to",
            "evidence_source": "passive_dns",
            "evidence_observation_id": observation_id,
        },
    )

    assert response.status_code == 201
    assert response.json()["evidence_observation_id"] == observation_id
