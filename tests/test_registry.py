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
        "supported_types": ["domain", "url"],
    }


def test_registry_rejects_unknown_requested_connector():
    with pytest.raises(ValueError, match="unknown source"):
        ConnectorRegistry([ExampleConnector]).build(Config(), ["missing"])


def test_engine_reports_provider_capabilities_without_keys():
    providers = Engine(Config()).provider_status()
    virustotal = next(provider for provider in providers if provider["name"] == "virustotal")

    assert virustotal["configured"] is False
    assert "sha256" in virustotal["supported_types"]
