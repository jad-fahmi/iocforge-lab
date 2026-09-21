import httpx
import respx
from ioc_enricher.connectors.urlhaus import URLhaus
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_urlhaus_flags_known_malware_url_and_sends_auth_header():
    route = respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "date_added": "2026-09-01 12:00:00 UTC",
                "tags": ["elf", "botnet"],
                "payloads": [{"response_sha256": "a" * 64}],
            },
        )
    )

    result = URLhaus(api_key="key").enrich("https://evil.example/a", IocType.URL)

    assert route.calls.last.request.headers["Auth-Key"] == "key"
    assert result.found is True
    assert result.malicious is True
    assert result.score == 1.0
    assert result.raw["payload_count"] == 1


@respx.mock
def test_urlhaus_no_results_is_not_an_error():
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )

    result = URLhaus(api_key="key").enrich("https://clean.example", IocType.URL)

    assert result.found is False
    assert result.error is None


def test_urlhaus_requires_a_key():
    result = URLhaus().enrich("https://evil.example/a", IocType.URL)

    assert result.error == "missing api key"
