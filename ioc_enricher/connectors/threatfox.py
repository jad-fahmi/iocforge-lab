"""ThreatFox IOC enrichment."""

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox(Connector):
    """Search abuse.ch's vetted malware IOC corpus using exact matches."""

    name = "threatfox"
    supported = (
        IocType.IPV4,
        IocType.IPV6,
        IocType.DOMAIN,
        IocType.URL,
        IocType.MD5,
        IocType.SHA1,
        IocType.SHA256,
        IocType.SHA512,
    )

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")
        try:
            response = self.post(
                BASE,
                json={"query": "search_ioc", "search_term": ioc, "exact_match": True},
                headers={"Auth-Key": self.api_key},
            )
        except Exception as exc:
            log.warning("ThreatFox request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))
        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")
        return self._parse(ioc, ioc_type, response.json())

    def _parse(self, ioc, ioc_type, payload) -> SourceResult:
        records = payload.get("data", [])
        if payload.get("query_status") in {"no_result", "no_results"}:
            return self._empty(ioc, ioc_type)
        if payload.get("query_status") != "ok" or not isinstance(records, list):
            return self._empty(
                ioc,
                ioc_type,
                error=f"provider response: {payload.get('query_status', 'unknown')}",
            )
        confidence = [
            float(record.get("confidence_level", 80)) / 100
            for record in records
            if str(record.get("confidence_level", "")).isdigit()
        ]
        tags = sorted(
            {
                tag
                for record in records
                for tag in record.get("tags", []) + [record.get("malware", "")]
                if tag
            }
        )[:20]
        raw = {
            "ioc_count": len(records),
            "threat_types": sorted(
                {
                    record.get("threat_type")
                    for record in records
                    if record.get("threat_type")
                }
            ),
            "malware": sorted(
                {record.get("malware") for record in records if record.get("malware")}
            ),
            "references": [
                record.get("reference")
                for record in records[:10]
                if record.get("reference")
            ],
        }
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious=True,
            score=max(confidence, default=0.8),
            raw=raw,
            tags=tags,
            observed_at=records[0].get("last_seen_utc")
            or records[0].get("first_seen_utc"),
        )
