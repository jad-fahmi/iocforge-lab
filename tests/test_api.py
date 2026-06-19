from fastapi.testclient import TestClient
from ioc_enricher.api import app as api_module
from ioc_enricher.api.rate_limit import RateLimiter
from ioc_enricher.config import Config
from ioc_enricher.engine import Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult


def _client(monkeypatch):
    engine = Engine(Config())
    engine.connectors = []
    monkeypatch.setattr(api_module, "get_engine", lambda: engine)
    return TestClient(api_module.app)


def test_versioned_enrich_endpoint_returns_typed_payload(monkeypatch):
    response = _client(monkeypatch).post("/api/v1/enrich", json={"ioc": "example.com"})

    assert response.status_code == 200
    assert response.json()["ioc_type"] == "domain"
    assert response.json()["sources"] == []


def test_api_rate_limit_returns_retry_headers(monkeypatch):
    monkeypatch.setattr(api_module, "rate_limiter", RateLimiter(limit=1, window_seconds=60))
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


def test_misp_export_endpoint_returns_unpublished_event(monkeypatch):
    response = _client(monkeypatch).post(
        "/api/v1/interoperability/misp/export",
        json={"iocs": ["example.com"], "info": "Case export"},
    )

    assert response.status_code == 200
    assert response.json()["Event"]["published"] is False
    assert response.json()["Event"]["Attribute"][0]["type"] == "domain"


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


def test_verdict_override_endpoint_requires_reason_and_can_be_cleared(monkeypatch, tmp_path):
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
        "/api/v1/investigations", json={"title": "Malware triage", "description": "Review"}
    )
    investigation_id = created.json()["id"]
    updated = client.post(
        f"/api/v1/investigations/{investigation_id}/indicators",
        json={"ioc": "evil.example"},
    )

    assert created.status_code == 201
    assert updated.json()["indicators"] == ["evil.example"]
    assert client.get(f"/api/v1/investigations/{investigation_id}/events").status_code == 200


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
