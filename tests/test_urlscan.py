import httpx
import respx
from ioc_enricher.connectors.urlscan import Urlscan
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_urlscan_returns_historical_scan_metadata_without_verdict_signal():
    route = respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 3,
                "results": [
                    {
                        "_id": "scan-id",
                        "page": {
                            "url": "https://example.com/a",
                            "domain": "example.com",
                            "country": "US",
                        },
                        "task": {
                            "time": "2026-09-20T10:00:00.000Z",
                            "visibility": "public",
                        },
                        "stats": {"uniqIPs": 2, "uniqDomains": 4},
                    }
                ],
            },
        )
    )

    result = Urlscan(api_key="key").enrich("https://example.com/a", IocType.URL)

    assert route.calls.last.request.headers["API-Key"] == "key"
    assert (
        route.calls.last.request.url.params["q"]
        == 'canonical.page.url:"https://example.com/a"'
    )
    assert result.found is True
    assert result.malicious is None
    assert result.raw["scan_count"] == 3
    assert result.observed_at == "2026-09-20T10:00:00.000Z"


@respx.mock
def test_urlscan_no_results_is_not_an_error():
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"total": 0, "results": []})
    )

    result = Urlscan(api_key="key").enrich("example.com", IocType.DOMAIN)

    assert result.found is False
    assert result.error is None


def test_urlscan_requires_a_key():
    result = Urlscan().enrich("example.com", IocType.DOMAIN)

    assert result.error == "missing api key"
