from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://api.greynoise.io/v3/community"


class GreyNoise(Connector):
    name = "greynoise"
    supported = (IocType.IPV4,)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")

        headers = {"key": self.api_key, "Accept": "application/json"}
        try:
            resp = self.get(f"{BASE}/{ioc}", headers=headers)
        except Exception as exc:
            log.warning("greynoise request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if resp.status_code == 404:
            return self._empty(ioc, ioc_type)
        if resp.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {resp.status_code}")

        data = resp.json()
        classification = data.get("classification", "unknown")
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious=classification == "malicious",
            raw={"classification": classification, "noise": data.get("noise")},
            tags=[data["name"]] if data.get("name") else [],
        )
