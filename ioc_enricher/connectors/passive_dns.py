"""CIRCL passive-DNS enrichment for historical domain and IP observations."""

import json
from datetime import datetime, timezone
from urllib.parse import quote

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://www.circl.lu/pdns/query"
MAX_RECORDS = 100


class PassiveDNS(Connector):
    """Query CIRCL historical DNS data without falling back to active DNS."""

    name = "passive_dns"
    requires_api_key = False
    supported = (IocType.IPV4, IocType.IPV6, IocType.DOMAIN)

    def enrich(self, ioc: str, ioc_type: IocType) -> SourceResult:
        try:
            response = self.get(
                f"{BASE}/{quote(ioc, safe='')}",
                max_retries=1,
                headers={"dribble-disable-active-query": "1"},
            )
        except Exception as exc:
            log.warning("passive DNS request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if response.status_code == 404:
            return self._empty(ioc, ioc_type)
        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")

        records: list[dict] = []
        malformed = 0
        for line in response.text.splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(record, dict):
                records.append(record)
            else:
                malformed += 1
            if len(records) >= MAX_RECORDS:
                break
        if not records:
            if malformed:
                return self._empty(ioc, ioc_type, error="invalid passive DNS response")
            return self._empty(ioc, ioc_type)

        timestamps: list[datetime] = []
        for record in records:
            timestamp = _timestamp(record.get("time_last"))
            if timestamp is not None:
                timestamps.append(timestamp)
        tags = sorted(
            {str(record["rrtype"]) for record in records if record.get("rrtype")}
        )
        raw = {
            "record_count": len(records),
            "records": records,
            "truncated": len(records) == MAX_RECORDS
            or bool(response.headers.get("x-dribble-errors")),
        }
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw=raw,
            tags=tags,
            observed_at=max(timestamps).isoformat() if timestamps else None,
        )


def _timestamp(value: object) -> datetime | None:
    """Convert a Passive DNS Common Output Format epoch to UTC safely."""
    try:
        return datetime.fromtimestamp(float(str(value)), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None
