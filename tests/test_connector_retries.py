from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
from ioc_enricher.config import Config
from ioc_enricher.connectors.base import Connector, _retry_after
from ioc_enricher.engine import Engine
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult


class RetryConnector(Connector):
    name = "retry-test"

    def enrich(self, ioc, ioc_type) -> SourceResult:
        return self._empty(ioc, ioc_type)


def test_retry_after_accepts_seconds_and_http_dates():
    assert _retry_after("4") == 4
    delay = _retry_after(
        format_datetime(datetime.now(timezone.utc) + timedelta(seconds=5))
    )
    assert 4 <= delay <= 5


def test_retry_after_bounds_invalid_and_non_finite_values():
    assert _retry_after(None) == 2
    assert _retry_after("invalid") == 2
    assert _retry_after("-4") == 0
    assert _retry_after("inf") == 2
    assert _retry_after("90") == 30


def test_rate_limited_response_retries_with_bounded_delay(monkeypatch):
    responses = iter((429, 200))
    delays = []

    def respond(_request):
        status = next(responses)
        headers = {"Retry-After": "-1"} if status == 429 else {}
        return httpx.Response(status, headers=headers)

    client = httpx.Client(transport=httpx.MockTransport(respond))
    monkeypatch.setattr("ioc_enricher.connectors.base.time.sleep", delays.append)

    response = RetryConnector(client=client).get("https://provider.example/lookup")

    assert response.status_code == 200
    assert delays == [0]


def test_connector_retry_configuration_controls_retry_count_and_backoff(monkeypatch):
    responses = iter((503, 200))
    delays = []

    def respond(_request):
        return httpx.Response(next(responses))

    client = httpx.Client(transport=httpx.MockTransport(respond))
    monkeypatch.setattr("ioc_enricher.connectors.base.time.sleep", delays.append)
    connector = RetryConnector(
        client=client,
        max_retries=1,
        backoff_base_seconds=0.25,
        max_retry_after_seconds=0.5,
    )

    assert connector.get("https://provider.example/lookup").status_code == 200
    assert delays == [0.25]


def test_retry_attempts_consume_provider_quota():
    responses = iter((503, 200))
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(next(responses))

    class EngineRetryConnector(Connector):
        name = "retry-test"
        supported = (IocType.DOMAIN,)

        def enrich(self, ioc, ioc_type):
            response = self.get("https://provider.example/lookup")
            response.raise_for_status()
            return SourceResult(
                source=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                found=True,
                malicious=False,
            )

    client = httpx.Client(transport=httpx.MockTransport(respond))
    config = Config(
        providers={
            "retry-test": {
                "requests_per_window": 1,
                "window_seconds": 0.04,
                "retries": 1,
                "backoff_base_seconds": 0,
            }
        }
    )
    engine = Engine(config, sources=[])
    engine.connectors = [EngineRetryConnector(client=client)]

    try:
        result = engine.enrich("example.com")
        assert result.sources[0].found is True
        assert len(requests) == 2
        assert result.sources[0].latency_ms >= 30
    finally:
        engine.close()
