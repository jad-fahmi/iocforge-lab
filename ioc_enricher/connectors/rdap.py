"""RDAP enrichment for public IP addresses and domain registrations."""

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://rdap.org"


class RDAP(Connector):
    """Query the public RDAP bootstrap service; no credential is required."""

    name = "rdap"
    requires_api_key = False
    supported = (IocType.IPV4, IocType.IPV6, IocType.DOMAIN)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        resource = "ip" if ioc_type in (IocType.IPV4, IocType.IPV6) else "domain"
        try:
            response = self.get(f"{BASE}/{resource}/{ioc}")
        except Exception as exc:
            log.warning("RDAP request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if response.status_code == 404:
            return self._empty(ioc, ioc_type)
        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")
        return self._parse(ioc, ioc_type, response.json())

    def _parse(self, ioc, ioc_type, payload) -> SourceResult:
        events = payload.get("events", [])
        last_changed = next(
            (
                event.get("eventDate")
                for event in events
                if event.get("eventAction") in {"last changed", "last update"}
            ),
            None,
        )
        tags = [
            value
            for value in (payload.get("objectClassName"), payload.get("type"))
            if value
        ]
        raw = {
            "handle": payload.get("handle"),
            "name": payload.get("name"),
            "status": payload.get("status", []),
            "country": payload.get("country"),
            "start_address": payload.get("startAddress"),
            "end_address": payload.get("endAddress"),
        }
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw={key: value for key, value in raw.items() if value is not None},
            tags=tags,
            observed_at=last_changed,
        )
