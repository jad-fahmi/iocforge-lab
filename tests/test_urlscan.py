import httpx
import respx
from ioc_enricher.connectors.urlscan import (
    MAX_HASH_PIVOTS_PER_KIND,
    RESULT_BASE,
    Urlscan,
)
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
                        "_id": "11111111-1111-4111-8111-111111111111",
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
    detail_route = respx.get(
        f"{RESULT_BASE}11111111-1111-4111-8111-111111111111/"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "lists": {"hashes": ["A" * 64, "not-a-hash"]},
                "meta": {
                    "processors": {
                        "download": {
                            "data": [
                                {"sha256": "b" * 64},
                                {"sha256": "also-not-a-hash"},
                            ]
                        }
                    }
                },
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
    assert result.raw["detail_result_status"] == "ok"
    assert result.raw["detail_result_http_status"] == 200
    assert result.raw["response_hashes"] == ["a" * 64]
    assert result.raw["downloaded_file_hashes"] == ["b" * 64]
    assert result.observed_at == "2026-09-20T10:00:00+00:00"
    assert detail_route.calls.call_count == 1
    assert result.related_entities == [
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "https://example.com/landing",
            "relationship_type": "scan_observed_url",
            "source_entity_type": "url",
            "target_entity_type": "url",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {
                "scan_id": "11111111-1111-4111-8111-111111111111",
                "source_field": "page.url",
            },
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "example.com",
            "relationship_type": "scan_observed_hostname",
            "source_entity_type": "url",
            "target_entity_type": "hostname",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {
                "scan_id": "11111111-1111-4111-8111-111111111111",
                "source_field": "page.domain",
            },
        },
        {
            "source_ioc": "https://example.com/a",
            "target_ioc": "203.0.113.7",
            "relationship_type": "scan_observed_ip",
            "source_entity_type": "url",
            "target_entity_type": "ip",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {
                "scan_id": "11111111-1111-4111-8111-111111111111",
                "source_field": "page.ip",
            },
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
        {
            "source_ioc": "https://example.com/landing",
            "target_ioc": "a" * 64,
            "relationship_type": "scan_response_sha256",
            "source_entity_type": "url",
            "target_entity_type": "file_hash",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {
                "scan_id": "11111111-1111-4111-8111-111111111111",
                "source_field": "lists.hashes",
            },
        },
        {
            "source_ioc": "https://example.com/landing",
            "target_ioc": "b" * 64,
            "relationship_type": "scan_downloaded_file_sha256",
            "source_entity_type": "url",
            "target_entity_type": "file_hash",
            "observed_at": "2026-09-20T10:00:00+00:00",
            "attributes": {
                "scan_id": "11111111-1111-4111-8111-111111111111",
                "source_field": "meta.processors.download.data[].sha256",
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


@respx.mock
def test_urlscan_detail_failure_preserves_search_pivots():
    scan_id = "22222222-2222-4222-8222-222222222222"
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 1,
                "results": [
                    {
                        "_id": scan_id,
                        "page": {"url": "https://example.com/path"},
                        "task": {"time": "2026-09-20T10:00:00Z"},
                    }
                ],
            },
        )
    )
    respx.get(f"{RESULT_BASE}{scan_id}/").mock(
        return_value=httpx.Response(410, json={"message": "result deleted"})
    )

    result = Urlscan(api_key="key").enrich("example.com", IocType.DOMAIN)

    assert result.found is True
    assert result.raw["detail_result_status"] == "unavailable"
    assert result.raw["detail_result_http_status"] == 410
    assert result.related_entities[0]["target_ioc"] == "https://example.com/path"
    assert len(result.related_entities) == 1


@respx.mock
def test_urlscan_caps_hash_pivots_by_kind():
    scan_id = "33333333-3333-4333-8333-333333333333"
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={"total": 1, "results": [{"_id": scan_id, "page": {}, "task": {}}]},
        )
    )
    respx.get(f"{RESULT_BASE}{scan_id}/").mock(
        return_value=httpx.Response(
            200,
            json={
                "lists": {"hashes": [f"{index:064x}" for index in range(30)]},
                "meta": {
                    "processors": {
                        "download": {
                            "data": [
                                {"sha256": f"{index + 100:064x}"}
                                for index in range(30)
                            ]
                        }
                    }
                },
            },
        )
    )

    result = Urlscan(api_key="key").enrich(
        "https://example.com/path", IocType.URL
    )

    assert result.raw["response_hash_count"] == 30
    assert result.raw["response_hashes_truncated"] is True
    assert result.raw["downloaded_file_hash_count"] == 30
    assert result.raw["downloaded_file_hashes_truncated"] is True
    assert len(result.raw["response_hashes"]) == MAX_HASH_PIVOTS_PER_KIND
    assert len(result.raw["downloaded_file_hashes"]) == MAX_HASH_PIVOTS_PER_KIND
    assert len(result.related_entities) == 2 * MAX_HASH_PIVOTS_PER_KIND


@respx.mock
def test_urlscan_hash_edges_retain_observation_provenance(tmp_path):
    scan_id = "44444444-4444-4444-8444-444444444444"
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 1,
                "results": [
                    {
                        "_id": scan_id,
                        "page": {"url": "https://example.com/path"},
                        "task": {"time": "2026-09-20T10:00:00Z"},
                    }
                ],
            },
        )
    )
    response_hash = "c" * 64
    respx.get(f"{RESULT_BASE}{scan_id}/").mock(
        return_value=httpx.Response(
            200,
            json={"lists": {"hashes": [response_hash]}},
        )
    )
    result = Urlscan(api_key="key").enrich("example.com", IocType.DOMAIN)
    enrichment = EnrichmentResult(ioc="example.com", ioc_type=IocType.DOMAIN)
    enrichment.add(result)
    store = HistoryStore(tmp_path / "history.db")

    enrichment_id = store.record(enrichment, looked_up_at="2026-09-21T00:00:00Z")
    observations = store.observations_for_enrichment(enrichment_id)
    graph = store.relationship_graph(
        "example.com", max_depth=2, as_of="2026-09-22T00:00:00Z"
    )
    hash_edge = next(
        edge
        for edge in graph["edges"]
        if edge["relationship_type"] == "scan_response_sha256"
    )

    assert len(observations) == 1
    assert hash_edge["target_ioc"] == response_hash
    assert hash_edge["source_ioc"] == "https://example.com/path"
    assert hash_edge["target_entity_type"] == "file_hash"
    assert hash_edge["evidence_source"] == "urlscan"
    assert hash_edge["evidence_observation_id"] == observations[0]["id"]
    assert hash_edge["valid_from"] == "2026-09-20T10:00:00+00:00"


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
