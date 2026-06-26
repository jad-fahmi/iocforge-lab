"""urlscan.io historical scan enrichment."""

from datetime import datetime, timezone

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://urlscan.io/api/v1/search/"
MAX_SEARCH_RESULTS = 10
PAGE_RELATIONSHIPS = {
    "url": ("scan_observed_url", {IocType.URL}, "url"),
    "domain": ("scan_observed_hostname", {IocType.DOMAIN}, "hostname"),
    "ip": ("scan_observed_ip", {IocType.IPV4, IocType.IPV6}, "ip"),
}


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
        if not isinstance(page, dict):
            page = {}
        if not isinstance(task, dict):
            task = {}
        if not isinstance(stats, dict):
            stats = {}
        scan_time = _timestamp(task.get("time"))
        reported_total = payload.get("total", len(results))
        if (
            isinstance(reported_total, bool)
            or not isinstance(reported_total, int)
            or reported_total < 0
        ):
            reported_total = len(results)
        used_results = min(len(results), MAX_SEARCH_RESULTS)
        raw = {
            "scan_count": reported_total,
            "scan_results_returned": len(results),
            "scan_results_used": used_results,
            "scan_result_limit": MAX_SEARCH_RESULTS,
            "scan_results_truncated": (
                reported_total > used_results or len(results) > MAX_SEARCH_RESULTS
            ),
            "scan_id": latest.get("_id"),
            "scan_time": task.get("time"),
            "page_url": page.get("url"),
            "page_domain": page.get("domain"),
            "page_ip": page.get("ip"),
            "country": page.get("country"),
            "uniq_ips": stats.get("uniqIPs"),
            "uniq_domains": stats.get("uniqDomains"),
        }
        tags = [
            value for value in (page.get("country"), task.get("visibility")) if value
        ]
        root_entity_type = {
            IocType.URL: "url",
            IocType.DOMAIN: "domain",
            IocType.IPV4: "ip",
            IocType.IPV6: "ip",
        }[ioc_type]
        root_value = normalize(ioc, ioc_type)
        related_entities = []
        for scan in results[:used_results]:
            if not isinstance(scan, dict):
                continue
            scan_page = scan.get("page", {})
            scan_task = scan.get("task", {})
            if not isinstance(scan_page, dict):
                scan_page = {}
            if not isinstance(scan_task, dict):
                scan_task = {}
            related_at = _timestamp(scan_task.get("time"))
            for field, (relationship_type, accepted_types, target_entity_type) in (
                PAGE_RELATIONSHIPS.items()
            ):
                value = scan_page.get(field)
                if not isinstance(value, str) or not value.strip():
                    continue
                target_value = value.strip()
                detected_type = detect(target_value)
                if detected_type not in accepted_types:
                    continue
                canonical_target = normalize(target_value, detected_type)
                if canonical_target == root_value:
                    continue
                related_entities.append(
                    {
                        "source_ioc": root_value,
                        "target_ioc": canonical_target,
                        "relationship_type": relationship_type,
                        "source_entity_type": root_entity_type,
                        "target_entity_type": target_entity_type,
                        "observed_at": related_at,
                        "attributes": {
                            "scan_id": scan.get("_id"),
                            "source_field": f"page.{field}",
                        },
                    }
                )
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw={key: value for key, value in raw.items() if value is not None},
            tags=tags,
            observed_at=scan_time,
            related_entities=related_entities,
        )


def _timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()
