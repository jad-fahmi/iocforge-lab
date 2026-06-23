import abc
import math
import time
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Lock
from typing import Callable

import httpx

from ioc_enricher.ioc.types import IocType
from ioc_enricher.log import get
from ioc_enricher.models import SourceResult

log = get(__name__)
_REQUEST_ADMISSION: ContextVar[Callable[[], None] | None] = ContextVar(
    "iocforge_request_admission", default=None
)


def set_request_admission(callback: Callable[[], None]) -> Token:
    """Set a per-lookup quota callback for this connector worker thread."""
    return _REQUEST_ADMISSION.set(callback)


def reset_request_admission(token: Token) -> None:
    _REQUEST_ADMISSION.reset(token)


def admit_request() -> None:
    callback = _REQUEST_ADMISSION.get()
    if callback is not None:
        callback()


class Connector(abc.ABC):
    """base class for a threat intel source."""

    name = "base"
    version = "1"
    normalization_version = "1"
    supported: tuple = ()
    requires_api_key = True

    def __init__(
        self,
        api_key=None,
        timeout=10.0,
        client=None,
        max_retries=2,
        backoff_base_seconds=1.0,
        max_retry_after_seconds=30.0,
    ):
        self.api_key = api_key
        self.timeout = _positive_number(timeout, "timeout")
        self._client = client
        self._client_lock = Lock()
        self.max_retries = _non_negative_number(max_retries, "max_retries", integer=True)
        self.backoff_base_seconds = _non_negative_number(
            backoff_base_seconds, "backoff_base_seconds"
        )
        self.max_retry_after_seconds = _non_negative_number(
            max_retry_after_seconds, "max_retry_after_seconds"
        )

    @property
    def client(self):
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in self.supported

    def _admit_request(self) -> None:
        admit_request()

    def request(self, method, url, max_retries=None, **kwargs):
        """Request with bounded retries for transient upstream failures."""
        max_retries = self.max_retries if max_retries is None else max_retries
        max_retries = _non_negative_number(max_retries, "max_retries", integer=True)
        attempt = 0
        while True:
            admit_request()
            try:
                resp = self.client.request(method, url, **kwargs)
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt >= max_retries:
                    raise
                wait = min(self.backoff_base_seconds * 2**attempt, self.max_retry_after_seconds)
                log.warning("%s request failed, retrying in %ss", self.name, wait)
                time.sleep(wait)
                attempt += 1
                continue

            if resp.status_code == 429 and attempt < max_retries:
                wait = _retry_after(
                    resp.headers.get("Retry-After"), self.max_retry_after_seconds
                )
                log.warning("%s rate limited, sleeping %ss", self.name, wait)
                time.sleep(wait)
                attempt += 1
                continue

            if resp.status_code >= 500 and attempt < max_retries:
                wait = min(self.backoff_base_seconds * 2**attempt, self.max_retry_after_seconds)
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

    def get(self, url, max_retries=None, **kwargs):
        return self.request("GET", url, max_retries=max_retries, **kwargs)

    def post(self, url, max_retries=None, **kwargs):
        return self.request("POST", url, max_retries=max_retries, **kwargs)

    @abc.abstractmethod
    def enrich(self, ioc: str, ioc_type: IocType) -> SourceResult: ...

    def _cached_result(
        self, ioc, cache, ioc_type: IocType | None = None
    ) -> SourceResult | None:
        hit = cache.get(self.name, ioc)
        if hit is None:
            return None
        result = self._source_from_cache(hit, ioc, ioc_type, cache)
        if result is None:
            return None
        if result.connector_version == "unknown":
            result.connector_version = self.version
        result.cache_hit = True
        return result

    def _source_from_cache(self, value, ioc, ioc_type, cache):
        try:
            if not isinstance(value, dict):
                raise ValueError("cached provider result is not an object")
            payload = dict(value)
            payload["ioc_type"] = IocType(payload["ioc_type"])
            result = SourceResult(**payload)
            if (
                result.source != self.name
                or result.ioc != ioc
                or (ioc_type is not None and result.ioc_type != ioc_type)
                or not isinstance(result.raw, dict)
                or not isinstance(result.tags, list)
                or any(not isinstance(tag, str) for tag in result.tags)
                or not isinstance(result.extraction_metadata, dict)
                or not isinstance(result.related_entities, list)
                or any(not isinstance(item, dict) for item in result.related_entities)
                or not (
                    result.freshness is None or isinstance(result.freshness, dict)
                )
                or not isinstance(result.found, bool)
                or (
                    result.malicious is not None
                    and not isinstance(result.malicious, bool)
                )
                or not (
                    result.error is None or isinstance(result.error, str)
                )
                or any(
                    item is not None
                    and (
                        not isinstance(item, (int, float))
                        or isinstance(item, bool)
                        or not math.isfinite(item)
                    )
                    for item in (result.score, result.confidence)
                )
            ):
                raise ValueError("cached provider result has invalid fields")
        except (KeyError, TypeError, ValueError, OverflowError):
            cache.delete(self.name, ioc)
            return None
        return result

    def run(self, ioc, ioc_type, cache=None, skip_fresh_cache=False) -> SourceResult:
        """enrich with an optional cache in front."""
        if cache is not None and not skip_fresh_cache:
            result = self._cached_result(ioc, cache, ioc_type)
            if result is not None:
                return result

        result = self.enrich(ioc, ioc_type)
        if result.connector_version == "unknown":
            result.connector_version = self.version
        if result.normalization_version == "1":
            result.normalization_version = self.normalization_version

        # An expired result is never used as a normal cache hit. It can only
        # keep an investigation moving when the live provider is unavailable,
        # and is labeled so analysts do not mistake it for fresh evidence.
        if cache is not None and result.error is not None:
            stale = cache.lookup(self.name, ioc, allow_stale=True)
            if stale is not None and stale.stale:
                stale_result = self._source_from_cache(
                    stale.value, ioc, ioc_type, cache
                )
                if stale_result is None:
                    return result
                raw = dict(stale_result.raw)
                raw.update(
                    {
                        "cache_stale": True,
                        "cache_age_seconds": round(stale.age_seconds, 3),
                        "live_lookup_error": result.error,
                    }
                )
                stale_result.raw = raw
                stale_result.tags = sorted(set(stale_result.tags) | {"stale_cache"})
                if stale_result.connector_version == "unknown":
                    stale_result.connector_version = self.version
                stale_result.cache_hit = True
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
            normalization_version=self.normalization_version,
        )


def _retry_after(value, maximum=30):
    if value is None:
        return min(2, maximum)
    try:
        delay = float(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            delay = (retry_at - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return min(2, maximum)
    if not math.isfinite(delay):
        return min(2, maximum)
    return min(max(delay, 0), maximum)


def _non_negative_number(value, name, integer=False):
    valid_type = isinstance(value, int) if integer else isinstance(value, (int, float))
    if (
        isinstance(value, bool)
        or not valid_type
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} must be finite and non-negative")
    return int(value) if integer else float(value)


def _positive_number(value, name):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be finite and positive")
    return float(value)
