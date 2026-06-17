"""CIRCL Hashlookup enrichment for known-file metadata."""

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://hashlookup.circl.lu/lookup"
HASH_TYPES = {IocType.MD5: "md5", IocType.SHA1: "sha1", IocType.SHA256: "sha256"}


class Hashlookup(Connector):
    """Look up known file metadata through CIRCL's public Hashlookup service."""

    name = "hashlookup"
    requires_api_key = False
    supported = tuple(HASH_TYPES)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        hash_type = HASH_TYPES[ioc_type]
        try:
            response = self.get(f"{BASE}/{hash_type}/{ioc}")
        except Exception as exc:
            log.warning("CIRCL Hashlookup request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))
        if response.status_code == 404:
            return self._empty(ioc, ioc_type)
        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")
        return self._parse(ioc, ioc_type, response.json())

    def _parse(self, ioc, ioc_type, payload) -> SourceResult:
        if not isinstance(payload, dict) or not payload:
            return self._empty(ioc, ioc_type)
        raw = {
            "file_name": payload.get("FileName"),
            "file_size": payload.get("FileSize"),
            "md5": payload.get("MD5"),
            "sha1": payload.get("SHA-1"),
            "sha256": payload.get("SHA-256"),
            "source": payload.get("source"),
            "database": payload.get("db"),
        }
        tags = [value for value in (raw["source"], raw["database"]) if value]
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw={key: value for key, value in raw.items() if value is not None},
            tags=tags,
        )
