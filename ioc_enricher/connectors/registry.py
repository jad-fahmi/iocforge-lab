"""Connector discovery and provider status reporting."""

from dataclasses import dataclass
from typing import Iterable, Type

from ioc_enricher.connectors.base import Connector
from ioc_enricher.ioc.types import IocType
from ioc_enricher.scoring import DEFAULT_WEIGHTS


@dataclass(frozen=True)
class ProviderStatus:
    """A safe-to-expose summary of a configured threat-intel provider."""

    name: str
    enabled: bool
    configured: bool
    available: bool
    requires_api_key: bool
    reliability: float
    supported_types: tuple[IocType, ...]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "configured": self.configured,
            "available": self.available,
            "requires_api_key": self.requires_api_key,
            "reliability": self.reliability,
            "supported_types": [ioc_type.value for ioc_type in self.supported_types],
        }


class ConnectorRegistry:
    """The single source of truth for available connector implementations."""

    def __init__(self, connector_types: Iterable[Type[Connector]] = ()):
        self._types: dict[str, Type[Connector]] = {}
        for connector_type in connector_types:
            self.register(connector_type)

    def register(self, connector_type: Type[Connector]) -> None:
        if not connector_type.name or connector_type.name == "base":
            raise ValueError("connectors must declare a non-empty name")
        if connector_type.name in self._types:
            raise ValueError(f"duplicate connector name: {connector_type.name}")
        self._types[connector_type.name] = connector_type

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._types)

    def build(self, config, sources=None) -> list[Connector]:
        requested = set(sources) if sources else None
        unknown = requested.difference(self._types) if requested else set()
        if unknown:
            raise ValueError(f"unknown source(s): {', '.join(sorted(unknown))}")
        return [
            connector_type(
                api_key=config.key_for(name),
                timeout=config.providers.get(name, {}).get(
                    "timeout_seconds", config.scheduler.get("timeout_seconds", 10.0)
                ),
                max_retries=config.providers.get(name, {}).get(
                    "retries", config.scheduler.get("retries", 2)
                ),
                backoff_base_seconds=config.providers.get(name, {}).get(
                    "backoff_base_seconds",
                    config.scheduler.get("backoff_base_seconds", 1.0),
                ),
                max_retry_after_seconds=config.providers.get(name, {}).get(
                    "max_retry_after_seconds",
                    config.scheduler.get("max_retry_after_seconds", 30.0),
                ),
            )
            for name, connector_type in self._types.items()
            if (requested is None or name in requested)
            and config.provider_enabled(name)
        ]

    def status(self, config) -> list[ProviderStatus]:
        return [
            ProviderStatus(
                name=name,
                enabled=config.provider_enabled(name),
                configured=bool(config.key_for(name)),
                available=(
                    config.provider_enabled(name)
                    and (
                        not connector_type.requires_api_key
                        or bool(config.key_for(name))
                    )
                ),
                requires_api_key=connector_type.requires_api_key,
                reliability=float(
                    config.scoring.get("weights", {}).get(
                        name, DEFAULT_WEIGHTS.get(name, 0.5)
                    )
                ),
                supported_types=connector_type.supported,
            )
            for name, connector_type in self._types.items()
        ]
