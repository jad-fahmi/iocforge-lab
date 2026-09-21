import httpx
import respx
from ioc_enricher.connectors.crtsh import CrtSh
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_crtsh_collects_unique_certificate_names_and_issuers():
    route = respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name_value": "www.example.com\n*.api.example.com",
                    "issuer_name": "C=US, O=Example CA",
                    "not_after": "2027-01-01T00:00:00+00:00",
                },
                {
                    "name_value": "WWW.EXAMPLE.COM",
                    "issuer_name": "C=US, O=Example CA",
                    "not_after": "2026-01-01T00:00:00+00:00",
                },
            ],
        )
    )

    result = CrtSh().enrich("example.com", IocType.DOMAIN)

    assert route.calls.last.request.url.params["q"] == "%.example.com"
    assert result.found is True
    assert result.malicious is None
    assert result.raw["names"] == ["api.example.com", "www.example.com"]
    assert result.raw["certificate_count"] == 2


@respx.mock
def test_crtsh_empty_result_is_no_data():
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))

    result = CrtSh().enrich("example.com", IocType.DOMAIN)

    assert result.found is False
    assert result.error is None
