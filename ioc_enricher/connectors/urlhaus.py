"""URLhaus malware-URL enrichment."""

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhaus(Connector):
    """Query the authenticated URLhaus lookup endpoint for malware URLs."""

    name = "urlhaus"
    supported = (IocType.URL,)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")
        try:
            response = self.post(
                BASE,
                data={"url": ioc},
                headers={"Auth-Key": self.api_key},
            )
        except Exception as exc:
            log.warning("URLhaus request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")
        return self._parse(ioc, ioc_type, response.json())

    def _parse(self, ioc, ioc_type, payload) -> SourceResult:
        if payload.get("query_status") == "no_results":
            return self._empty(ioc, ioc_type)
        if payload.get("query_status") != "ok":
            return self._empty(
                ioc,
                ioc_type,
                error=f"provider response: {payload.get('query_status', 'unknown')}",
            )
        raw = {
            "url_status": payload.get("url_status"),
            "threat": payload.get("threat"),
            "date_added": payload.get("date_added"),
            "last_online": payload.get("last_online"),
            "urlhaus_reference": payload.get("urlhaus_reference"),
            "payload_count": len(payload.get("payloads", [])),
        }
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious=True,
            score=1.0,
            raw={key: value for key, value in raw.items() if value is not None},
            tags=list(payload.get("tags", []))[:10],
            observed_at=payload.get("last_online") or payload.get("date_added"),
        )
