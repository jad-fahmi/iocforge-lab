import base64

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(Connector):
    name = "virustotal"
    supported = (
        IocType.IPV4,
        IocType.IPV6,
        IocType.DOMAIN,
        IocType.URL,
        IocType.MD5,
        IocType.SHA1,
        IocType.SHA256,
    )

    def _path(self, ioc, ioc_type):
        if ioc_type in (IocType.IPV4, IocType.IPV6):
            return f"/ip_addresses/{ioc}"
        if ioc_type == IocType.DOMAIN:
            return f"/domains/{ioc}"
        if ioc_type == IocType.URL:
            ident = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            return f"/urls/{ident}"
        if ioc_type.is_hash():
            return f"/files/{ioc}"
        return None

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")

        path = self._path(ioc, ioc_type)
        if path is None:
            return self._empty(ioc, ioc_type, error="unsupported type")

        headers = {"x-apikey": self.api_key}
        try:
            resp = self.get(BASE + path, headers=headers)
        except Exception as exc:  # network error
            log.warning("vt request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if resp.status_code == 404:
            return self._empty(ioc, ioc_type)
        if resp.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {resp.status_code}")

        return self._parse(ioc, ioc_type, resp.json())

    def _parse(self, ioc, ioc_type, payload):
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious=(malicious + suspicious) > 0,
            score=round((malicious + suspicious) / total, 3),
            raw={"stats": stats},
            tags=list(attrs.get("tags", []))[:10],
        )
