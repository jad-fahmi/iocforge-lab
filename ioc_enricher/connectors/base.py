import abc
import math
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from ioc_enricher.ioc.types import IocType
from ioc_enricher.log import get
from ioc_enricher.models import SourceResult

log = get(__name__)


class Connector(abc.ABC):
    """base class for a threat intel source."""

    name = "base"
    version = "1"
    supported: tuple = ()
    requires_api_key = True

    def __init__(self, api_key=None, timeout=10.0, client=None):
        self.api_key = api_key
        self.timeout = timeout
        self._client = client

    @property
    def client(self):
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in self.supported

    def request(self, method, url, max_retries=2, **kwargs):
        """Request with bounded retries for transient upstream failures."""
        attempt = 0
        while True:
            try:
                resp = self.client.request(method, url, **kwargs)
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt >= max_retries:
                    raise
                wait = min(2**attempt, 30)
                log.warning("%s request failed, retrying in %ss", self.name, wait)
                time.sleep(wait)
                attempt += 1
                continue

            if resp.status_code == 429 and attempt < max_retries:
                wait = _retry_after(resp.headers.get("Retry-After"))
                log.warning("%s rate limited, sleeping %ss", self.name, wait)
                time.sleep(wait)
                attempt += 1
                continue

            if resp.status_code >= 500 and attempt < max_retries:
                wait = min(2**attempt, 30)
                log.warning(
                    "%s server error %s, retrying in %ss",
                    self.name,
                    resp.status_code,
                    wait,
                )
                time.sleep(wait)
                attempt += 1
                continue

            return resp

    def get(self, url, max_retries=2, **kwargs):
        return self.request("GET", url, max_retries=max_retries, **kwargs)

    def post(self, url, max_retries=2, **kwargs):
        return self.request("POST", url, max_retries=max_retries, **kwargs)

    @abc.abstractmethod
    def enrich(self, ioc: str, ioc_type: IocType) -> SourceResult: ...

    def run(self, ioc, ioc_type, cache=None) -> SourceResult:
        """enrich with an optional cache in front."""
        if cache is not None:
            hit = cache.get(self.name, ioc)
            if hit is not None:
                hit["ioc_type"] = IocType(hit["ioc_type"])
                result = SourceResult(**hit)
                if result.connector_version == "unknown":
                    result.connector_version = self.version
                return result

        result = self.enrich(ioc, ioc_type)
        if result.connector_version == "unknown":
            result.connector_version = self.version

        # An expired result is never used as a normal cache hit. It can only
        # keep an investigation moving when the live provider is unavailable,
        # and is labeled so analysts do not mistake it for fresh evidence.
        if cache is not None and result.error is not None:
            stale = cache.lookup(self.name, ioc, allow_stale=True)
            if stale is not None and stale.stale:
                payload = dict(stale.value)
                raw = dict(payload.get("raw", {}))
                raw.update(
                    {
                        "cache_stale": True,
                        "cache_age_seconds": round(stale.age_seconds, 3),
                        "live_lookup_error": result.error,
                    }
                )
                payload["raw"] = raw
                payload["tags"] = sorted(set(payload.get("tags", [])) | {"stale_cache"})
                payload["ioc_type"] = IocType(payload["ioc_type"])
                stale_result = SourceResult(**payload)
                if stale_result.connector_version == "unknown":
                    stale_result.connector_version = self.version
                return stale_result

        # only cache real answers, not transient errors
        if cache is not None and result.error is None:
            cache.set(self.name, ioc, result.to_dict())
        return result

    def _empty(self, ioc, ioc_type, error=None):
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=error,
            connector_version=self.version,
        )


def _retry_after(value):
    if value is None:
        return 2
    try:
        delay = float(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            delay = (retry_at - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return 2
    if not math.isfinite(delay):
        return 2
    return min(max(delay, 0), 30)
