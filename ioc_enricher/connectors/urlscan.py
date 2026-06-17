"""urlscan.io historical scan enrichment."""

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://urlscan.io/api/v1/search/"


class Urlscan(Connector):
    """Search urlscan.io's existing scans without submitting a new scan."""

    name = "urlscan"
    supported = (IocType.URL, IocType.DOMAIN, IocType.IPV4, IocType.IPV6)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")
        try:
            response = self.get(
                BASE,
                params={"q": self._query(ioc, ioc_type), "size": 10},
                headers={"API-Key": self.api_key},
            )
        except Exception as exc:
            log.warning("urlscan.io request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))
        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")
        return self._parse(ioc, ioc_type, response.json())

    @staticmethod
    def _query(ioc, ioc_type):
        escaped = ioc.replace("\\", "\\\\").replace('"', '\\"')
        field = {
            IocType.URL: "canonical.page.url",
            IocType.DOMAIN: "domain",
            IocType.IPV4: "ip",
            IocType.IPV6: "ip",
        }[ioc_type]
        return f'{field}:"{escaped}"'

    def _parse(self, ioc, ioc_type, payload) -> SourceResult:
        results = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(results, list) or not results:
            return self._empty(ioc, ioc_type)
        latest = results[0] if isinstance(results[0], dict) else {}
        page = latest.get("page", {})
        task = latest.get("task", {})
        stats = latest.get("stats", {})
        raw = {
            "scan_count": payload.get("total", len(results)),
            "scan_id": latest.get("_id"),
            "scan_time": task.get("time"),
            "page_url": page.get("url"),
            "page_domain": page.get("domain"),
            "page_ip": page.get("ip"),
            "country": page.get("country"),
            "uniq_ips": stats.get("uniqIPs"),
            "uniq_domains": stats.get("uniqDomains"),
        }
        tags = [value for value in (page.get("country"), task.get("visibility")) if value]
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw={key: value for key, value in raw.items() if value is not None},
            tags=tags,
            observed_at=task.get("time"),
        )
