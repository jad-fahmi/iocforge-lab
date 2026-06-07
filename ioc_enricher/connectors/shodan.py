from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://api.shodan.io"


class Shodan(Connector):
    name = "shodan"
    supported = (IocType.IPV4, IocType.IPV6)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")

        url = f"{BASE}/shodan/host/{ioc}"
        try:
            resp = self.client.get(url, params={"key": self.api_key})
        except Exception as exc:
            log.warning("shodan request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if resp.status_code == 404:
            return self._empty(ioc, ioc_type)
        if resp.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {resp.status_code}")

        data = resp.json()
        ports = data.get("ports", [])
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious=None,  # shodan is informational, not a verdict
            raw={"ports": ports, "org": data.get("org"), "os": data.get("os")},
            tags=list(data.get("tags", []))[:10],
        )
