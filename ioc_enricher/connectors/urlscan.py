"""urlscan.io historical scan enrichment."""

from datetime import datetime, timezone
from uuid import UUID

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://urlscan.io/api/v1/search/"
RESULT_BASE = "https://urlscan.io/api/v1/result/"
MAX_SEARCH_RESULTS = 10
MAX_HASH_PIVOTS_PER_KIND = 25
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
        result = self._parse(ioc, ioc_type, response.json())
        scan_id = result.raw.get("scan_id")
        if result.found:
            self._add_result_hashes(result, scan_id)
        return result

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

    def _add_result_hashes(self, result: SourceResult, scan_id: object) -> None:
        """Fetch one full scan result to add bounded file-hash pivots."""
        result.raw["detail_result_limit"] = 1
        if not result.found:
            return
        if not isinstance(scan_id, str):
            result.raw["detail_result_status"] = "missing_scan_id"
            return
        try:
            canonical_scan_id = str(UUID(scan_id))
        except (AttributeError, TypeError, ValueError):
            result.raw["detail_result_status"] = "invalid_scan_id"
            return

        try:
            response = self.get(
                f"{RESULT_BASE}{canonical_scan_id}/",
                headers={"API-Key": self.api_key},
            )
        except Exception as error:
            result.raw["detail_result_status"] = "request_error"
            result.raw["detail_result_error"] = str(error)
            return

        result.raw["detail_result_http_status"] = response.status_code
        if response.status_code != 200:
            result.raw["detail_result_status"] = "unavailable"
            return
        try:
            payload = response.json()
        except ValueError:
            result.raw["detail_result_status"] = "invalid_json"
            return
        if not isinstance(payload, dict):
            result.raw["detail_result_status"] = "invalid_payload"
            return

        lists = payload.get("lists", {})
        if not isinstance(lists, dict):
            lists = {}
        response_hashes = lists.get("hashes", [])
        if not isinstance(response_hashes, list):
            response_hashes = []

        processors = payload.get("meta", {})
        if not isinstance(processors, dict):
            processors = {}
        processors = processors.get("processors", {})
        if not isinstance(processors, dict):
            processors = {}
        download = processors.get("download", {})
        if not isinstance(download, dict):
            download = {}
        download_records = download.get("data", [])
        if not isinstance(download_records, list):
            download_records = []

        valid_response_hashes = _valid_sha256_values(response_hashes)
        valid_download_hashes = _valid_sha256_values(
            [
                record.get("sha256")
                for record in download_records
                if isinstance(record, dict)
            ]
        )
        selected_response_hashes = valid_response_hashes[:MAX_HASH_PIVOTS_PER_KIND]
        selected_download_hashes = valid_download_hashes[:MAX_HASH_PIVOTS_PER_KIND]
        result.raw.update(
            {
                "detail_result_status": "ok",
                "response_hashes": selected_response_hashes,
                "response_hash_count": len(valid_response_hashes),
                "response_hashes_truncated": len(valid_response_hashes)
                > MAX_HASH_PIVOTS_PER_KIND,
                "downloaded_file_hashes": selected_download_hashes,
                "downloaded_file_count": len(download_records),
                "downloaded_file_hash_count": len(valid_download_hashes),
                "downloaded_file_hashes_truncated": len(valid_download_hashes)
                > MAX_HASH_PIVOTS_PER_KIND,
            }
        )
        page_url = result.raw.get("page_url")
        if isinstance(page_url, str) and detect(page_url) == IocType.URL:
            hash_source_ioc = normalize(page_url, IocType.URL)
            hash_source_type = "url"
        else:
            hash_source_ioc = normalize(result.ioc, result.ioc_type)
            hash_source_type = {
                IocType.URL: "url",
                IocType.DOMAIN: "domain",
                IocType.IPV4: "ip",
                IocType.IPV6: "ip",
            }[result.ioc_type]
        for field, relationship_type, values in (
            ("lists.hashes", "scan_response_sha256", selected_response_hashes),
            (
                "meta.processors.download.data[].sha256",
                "scan_downloaded_file_sha256",
                selected_download_hashes,
            ),
        ):
            for value in values:
                result.related_entities.append(
                    {
                        "source_ioc": hash_source_ioc,
                        "target_ioc": value,
                        "relationship_type": relationship_type,
                        "source_entity_type": hash_source_type,
                        "target_entity_type": "file_hash",
                        "observed_at": result.observed_at,
                        "attributes": {
                            "scan_id": canonical_scan_id,
                            "source_field": field,
                        },
                    }
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


def _valid_sha256_values(values):
    selected = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or detect(value) != IocType.SHA256:
            continue
        normalized = normalize(value, IocType.SHA256)
        if normalized not in seen:
            selected.append(normalized)
            seen.add(normalized)
    return selected
