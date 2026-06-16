from fastapi.testclient import TestClient
from ioc_enricher.api import app as api_module
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
