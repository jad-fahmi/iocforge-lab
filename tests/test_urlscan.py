import httpx
import respx
from ioc_enricher.connectors.urlscan import Urlscan
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult


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
                            "url": "https://example.com/landing",
                            "domain": "example.com",
                            "ip": "203.0.113.7",
                            "country": "US",
                        },
                        "task": {
                            "time": "2026-09-20T10:00:00.000Z",
                            "visibility": "public",
                        },
                        "stats": {"uniqIPs": 2, "uniqDomains": 4},
                    },
                    {
                        "_id": "older-scan-id",
                        "page": {
                            "url": "https://example.net/old",
                            "domain": "example.net",
                            "ip": "198.51.100.9",
                        },
                        "task": {"time": "2026-09-19T08:00:00Z"},
                    },
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
    assert result.raw["scan_results_returned"] == 2
    assert result.raw["scan_results_used"] == 2
    assert result.raw["scan_result_limit"] == 10
    assert result.raw["scan_results_truncated"] is True
    assert result.observed_at == "2026-09-20T10:00:00+00:00"
    assert result.related_entities == [
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "https://example.com/landing",
            "relationship_type": "scan_observed_url",
            "source_entity_type": "url",
            "target_entity_type": "url",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {"scan_id": "scan-id", "source_field": "page.url"},
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "example.com",
            "relationship_type": "scan_observed_hostname",
            "source_entity_type": "url",
            "target_entity_type": "hostname",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {"scan_id": "scan-id", "source_field": "page.domain"},
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "203.0.113.7",
            "relationship_type": "scan_observed_ip",
            "source_entity_type": "url",
            "target_entity_type": "ip",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {"scan_id": "scan-id", "source_field": "page.ip"},
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "https://example.net/old",
            "relationship_type": "scan_observed_url",
            "source_entity_type": "url",
            "target_entity_type": "url",
            "observed_at": "2026-09-19T08:00:00+00:00",
            "attributes": {
                "scan_id": "older-scan-id",
                "source_field": "page.url",
            },
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "example.net",
            "relationship_type": "scan_observed_hostname",
            "source_entity_type": "url",
            "target_entity_type": "hostname",
            "observed_at": "2026-09-19T08:00:00+00:00",
            "attributes": {
                "scan_id": "older-scan-id",
                "source_field": "page.domain",
            },
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "198.51.100.9",
            "relationship_type": "scan_observed_ip",
            "source_entity_type": "url",
            "target_entity_type": "ip",
            "observed_at": "2026-09-19T08:00:00+00:00",
            "attributes": {
                "scan_id": "older-scan-id",
                "source_field": "page.ip",
            },
        },
    ]


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


def test_urlscan_limits_historical_relationship_expansion_to_ten_scans():
    payload = {
        "total": 20,
        "results": [
            {
                "_id": f"scan-{index}",
                "page": {
                    "url": f"https://host{index}.example.net/",
                    "domain": f"host{index}.example.net",
                    "ip": f"198.51.100.{index + 1}",
                },
                "task": {"time": f"2026-09-{index + 1:02d}T00:00:00Z"},
            }
            for index in range(12)
        ],
    }

    result = Urlscan()._parse("example.com", IocType.DOMAIN, payload)

    assert result.raw["scan_results_returned"] == 12
    assert result.raw["scan_results_used"] == 10
    assert result.raw["scan_results_truncated"] is True
    assert len(result.related_entities) == 30
    assert {edge["attributes"]["scan_id"] for edge in result.related_entities} == {
        f"scan-{index}" for index in range(10)
    }


def test_urlscan_backfilled_scans_do_not_appear_before_retrieval(tmp_path):
    result = Urlscan()._parse(
        "example.com",
        IocType.DOMAIN,
        {
            "total": 2,
            "results": [
                {
                    "_id": "newer",
                    "page": {
                        "url": "https://example.com/new",
                        "domain": "example.com",
                        "ip": "198.51.100.2",
                    },
                    "task": {"time": "2026-01-20T00:00:00Z"},
                },
                {
                    "_id": "older",
                    "page": {
                        "url": "https://example.com/old",
                        "domain": "example.com",
                        "ip": "198.51.100.1",
                    },
                    "task": {"time": "2026-01-10T00:00:00Z"},
                },
            ],
        },
    )
    enrichment = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    enrichment.add(result)
    store = HistoryStore(tmp_path / "history.db")
    store.record(enrichment, looked_up_at="2026-01-25T00:00:00Z")

    historical = store.relationship_graph(
        "example.com", as_of="2026-01-15T00:00:00Z", max_depth=1
    )
    current = store.relationship_graph(
        "example.com", as_of="2026-01-26T00:00:00Z", max_depth=1
    )

    assert historical["edges"] == []
    assert {edge["target_ioc"] for edge in current["edges"]} == {
        "https://example.com/old",
        "198.51.100.1",
        "https://example.com/new",
        "198.51.100.2",
    }
    recorded = store.relationships("example.com")
    scan_times = {edge["attributes"]["scan_id"]: edge["valid_from"] for edge in recorded}
    assert scan_times == {
        "older": "2026-01-10T00:00:00+00:00",
        "newer": "2026-01-20T00:00:00+00:00",
    }
