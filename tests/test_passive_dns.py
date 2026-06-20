import httpx
import respx
from ioc_enricher.connectors.passive_dns import PassiveDNS
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_passive_dns_returns_historical_records_without_a_verdict_signal():
    route = respx.get("https://www.circl.lu/pdns/query/example.com").mock(
        return_value=httpx.Response(
            200,
            text=(
                '{"rrtype":"A","rrname":"example.com","rdata":"203.0.113.5","time_last":1700000000}\n'
                '{"rrtype":"MX","rrname":"example.com","rdata":"mail.example.com","time_last":"1700000100"}\n'
            ),
        )
    )

    result = PassiveDNS().enrich("example.com", IocType.DOMAIN)

    assert route.called
    assert route.calls[0].request.headers["dribble-disable-active-query"] == "1"
    assert result.found is True
    assert result.malicious is None
    assert result.raw["record_count"] == 2
    assert result.tags == ["A", "MX"]
    assert result.observed_at == "2023-11-14T22:15:00+00:00"


@respx.mock
def test_passive_dns_returns_no_data_for_a_missing_observation():
    respx.get("https://www.circl.lu/pdns/query/192.0.2.1").mock(
        return_value=httpx.Response(404)
    )

    result = PassiveDNS().enrich("192.0.2.1", IocType.IPV4)

    assert result.found is False
    assert result.error is None


@respx.mock
def test_passive_dns_rejects_a_malformed_nonempty_response():
    respx.get("https://www.circl.lu/pdns/query/example.com").mock(
        return_value=httpx.Response(200, text="not json\n")
    )

    result = PassiveDNS().enrich("example.com", IocType.DOMAIN)

    assert result.found is False
    assert result.error == "invalid passive DNS response"
