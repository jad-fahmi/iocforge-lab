import httpx
import respx
from ioc_enricher.connectors.threatfox import ThreatFox
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_threatfox_returns_curated_malware_evidence():
    route = respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [{
                    "ioc": "evil.example",
                    "threat_type": "botnet_cc",
                    "malware": "win.example",
                    "confidence_level": 90,
                    "tags": ["c2"],
                    "reference": "https://example.test/report",
                    "last_seen_utc": "2026-09-01T00:00:00Z",
                }],
            },
        )
    )

    result = ThreatFox(api_key="key").enrich("evil.example", IocType.DOMAIN)

    assert route.calls.last.request.headers["Auth-Key"] == "key"
    assert result.malicious is True
    assert result.score == 0.9
    assert result.tags == ["c2", "win.example"]
    assert result.raw["threat_types"] == ["botnet_cc"]


@respx.mock
def test_threatfox_no_result_is_not_an_error():
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_result"})
    )

    result = ThreatFox(api_key="key").enrich("clean.example", IocType.DOMAIN)

    assert result.found is False
    assert result.error is None


def test_threatfox_requires_a_key():
    result = ThreatFox().enrich("evil.example", IocType.DOMAIN)

    assert result.error == "missing api key"
