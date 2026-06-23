from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDB(Connector):
    name = "abuseipdb"
    supported = (IocType.IPV4, IocType.IPV6)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        if not self.api_key:
            return self._empty(ioc, ioc_type, error="missing api key")

        headers = {"Authorization": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc, "maxAgeInDays": 90}
        try:
            resp = self.client.get(BASE + "/check", headers=headers, params=params)
        except Exception as exc:
            log.warning("abuseipdb request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if resp.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {resp.status_code}")

        data = resp.json().get("data", {})
        confidence = data.get("abuseConfidenceScore", 0)
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            malicious=confidence >= 25,
            score=round(confidence / 100, 3),
            raw={"abuseConfidenceScore": confidence,
                 "totalReports": data.get("totalReports")},
            tags=[data["usageType"]] if data.get("usageType") else [],
        )
