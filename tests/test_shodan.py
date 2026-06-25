import httpx
import respx
from ioc_enricher.connectors.shodan import Shodan
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_shodan_emits_validated_asn_and_hostname_relationships():
    respx.get("https://api.shodan.io/shodan/host/203.0.113.7").mock(
        return_value=httpx.Response(
            200,
            json={
                "ports": [443],
                "asn": "as64500",
                "hostnames": [
                    "WWW.Example.com.",
                    "bücher.example",
                    "not a hostname",
                    7,
                ],
                "org": "Example Networks",
                "os": None,
            },
        )
    )

    result = Shodan(api_key="fixture-key").enrich("203.0.113.7", IocType.IPV4)

    assert result.found is True
    assert result.malicious is None
    assert result.raw["asn"] == "as64500"
    assert result.raw["hostnames"] == [
        "WWW.Example.com.",
        "bücher.example",
        "not a hostname",
        7,
    ]
    assert result.related_entities == [
        {
            "source_ioc": "203.0.113.7",
            "target_ioc": "AS64500",
            "relationship_type": "announced_by",
            "source_entity_type": "ip",
            "target_entity_type": "asn",
            "attributes": {"source_field": "asn"},
        },
        {
            "source_ioc": "203.0.113.7",
            "target_ioc": "www.example.com",
            "relationship_type": "observed_hostname",
            "source_entity_type": "ip",
            "target_entity_type": "hostname",
            "attributes": {"source_field": "hostnames"},
        },
        {
            "source_ioc": "203.0.113.7",
            "target_ioc": "xn--bcher-kva.example",
            "relationship_type": "observed_hostname",
            "source_entity_type": "ip",
            "target_entity_type": "hostname",
            "attributes": {"source_field": "hostnames"},
        },
    ]
