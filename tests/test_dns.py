from unittest.mock import Mock

import dns.resolver
from ioc_enricher.connectors.dns import DNS
from ioc_enricher.ioc.types import IocType


def test_dns_returns_available_record_sets(monkeypatch):
    resolver = Mock()

    def resolve(_ioc, record_type):
        if record_type == "A":
            return ["203.0.113.7"]
        if record_type == "MX":
            return ["10 mail.example.com."]
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = resolve
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)

    result = DNS().enrich("example.com", IocType.DOMAIN)

    assert result.found is True
    assert result.raw["records"] == {
        "A": ["203.0.113.7"],
        "MX": ["10 mail.example.com"],
    }
    assert result.tags == ["dns:a", "dns:mx"]
    assert result.related_entities == [
        {
            "source_ioc": "example.com",
            "target_ioc": "203.0.113.7",
            "relationship_type": "resolves_to",
            "source_entity_type": "domain",
            "target_entity_type": "ip",
            "attributes": {"record_type": "A"},
        },
        {
            "source_ioc": "example.com",
            "target_ioc": "mail.example.com",
            "relationship_type": "mail_exchange",
            "source_entity_type": "domain",
            "target_entity_type": "hostname",
            "attributes": {"record_type": "MX"},
        },
    ]
def test_dns_returns_soft_error_for_timeout(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = dns.exception.Timeout("timed out")
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)

    result = DNS().enrich("example.com", IocType.DOMAIN)

    assert result.found is False
    assert result.error == "timed out"


def test_dns_returns_no_data_when_no_record_type_has_an_answer(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = dns.resolver.NoAnswer()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)

    result = DNS().enrich("example.com", IocType.DOMAIN)

    assert result.found is False
    assert result.error is None
