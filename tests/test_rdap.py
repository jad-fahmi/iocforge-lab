import httpx
import respx
from ioc_enricher.connectors.rdap import RDAP
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_rdap_enriches_domain_without_api_key():
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json={
            "objectClassName": "domain",
            "handle": "EXAMPLE1",
            "status": ["active"],
            "events": [{"eventAction": "last changed", "eventDate": "2025-01-02T00:00:00Z"}],
        })
    )

    result = RDAP().enrich("example.com", IocType.DOMAIN)

    assert result.found is True
    assert result.malicious is None
    assert result.raw["handle"] == "EXAMPLE1"
    assert result.observed_at == "2025-01-02T00:00:00Z"


@respx.mock
def test_rdap_returns_no_data_for_unknown_ip():
    respx.get("https://rdap.org/ip/192.0.2.1").mock(return_value=httpx.Response(404))

    result = RDAP().enrich("192.0.2.1", IocType.IPV4)

    assert result.found is False
    assert result.error is None
