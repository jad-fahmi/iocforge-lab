import pytest
from ioc_enricher.config import Config
from ioc_enricher.connectors.base import Connector
from ioc_enricher.connectors.registry import ConnectorRegistry
from ioc_enricher.engine import Engine
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult


class ExampleConnector(Connector):
    name = "example"
    supported = (IocType.DOMAIN, IocType.URL)

    def enrich(self, ioc, ioc_type):
        return SourceResult(source=self.name, ioc=ioc, ioc_type=ioc_type)


def test_registry_builds_only_enabled_requested_connectors():
    registry = ConnectorRegistry([ExampleConnector])
    config = Config(keys={"example": "key"}, providers={"example": {"enabled": False}})

    assert registry.build(config) == []
    assert registry.status(config)[0].to_dict() == {
        "name": "example",
        "enabled": False,
        "configured": True,
        "available": False,
        "requires_api_key": True,
        "reliability": 0.5,
        "supported_types": ["domain", "url"],
    }


def test_registry_rejects_unknown_requested_connector():
    with pytest.raises(ValueError, match="unknown source"):
        ConnectorRegistry([ExampleConnector]).build(Config(), ["missing"])


def test_engine_reports_provider_capabilities_without_keys():
    providers = Engine(Config()).provider_status()
    virustotal = next(provider for provider in providers if provider["name"] == "virustotal")

    assert virustotal["configured"] is False
    assert virustotal["available"] is False
    assert "sha256" in virustotal["supported_types"]
    assert virustotal["reliability"] == 1.0
    passive_dns = next(provider for provider in providers if provider["name"] == "passive_dns")
    assert passive_dns["available"] is True
    assert passive_dns["supported_types"] == ["ipv4", "ipv6", "domain"]


def test_provider_status_uses_configured_reliability_weight():
    providers = Engine(Config(scoring={"weights": {"rdap": 0.2}})).provider_status()
    rdap = next(provider for provider in providers if provider["name"] == "rdap")

    assert rdap["reliability"] == 0.2
