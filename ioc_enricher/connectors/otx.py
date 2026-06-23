from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTX(Connector):
    name = "otx"
    supported = (
        IocType.IPV4,
        IocType.IPV6,
        IocType.DOMAIN,
        IocType.URL,
        IocType.MD5,
        IocType.SHA1,
        IocType.SHA256,
    )

    def _section(self, ioc_type):
        if ioc_type == IocType.IPV4:
            return "IPv4"
        if ioc_type == IocType.IPV6:
            return "IPv6"
        if ioc_type == IocType.DOMAIN:
            return "domain"
        if ioc_type == IocType.URL:
            return "url"
        if ioc_type.is_hash():
            return "file"
        return None

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")

        section = self._section(ioc_type)
        if section is None:
            return self._empty(ioc, ioc_type, error="unsupported type")

        url = f"{BASE}/{section}/{ioc}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        try:
            resp = self.client.get(url, headers=headers)
        except Exception as exc:
            log.warning("otx request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if resp.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {resp.status_code}")

        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=pulses > 0,
            malicious=pulses > 0,
            score=1.0 if pulses > 2 else (0.5 if pulses else 0.0),
            raw={"pulse_count": pulses},
        )
