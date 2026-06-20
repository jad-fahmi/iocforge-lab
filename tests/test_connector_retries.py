from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
from ioc_enricher.connectors.base import Connector, _retry_after
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
