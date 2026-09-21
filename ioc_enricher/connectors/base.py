import abc
import time

import httpx

from ioc_enricher.ioc.types import IocType
from ioc_enricher.log import get
from ioc_enricher.models import SourceResult

log = get(__name__)


class Connector(abc.ABC):
    """base class for a threat intel source."""

    name = "base"
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
                wait = min(2 ** attempt, 30)
                log.warning("%s request failed, retrying in %ss", self.name, wait)
                time.sleep(wait)
                attempt += 1
                continue

            if resp.status_code == 429 and attempt < max_retries:
                try:
                    wait = float(resp.headers.get("Retry-After", 2))
                except ValueError:
                    wait = 2
                log.warning("%s rate limited, sleeping %ss", self.name, wait)
                time.sleep(min(wait, 30))
                attempt += 1
                continue

            if resp.status_code >= 500 and attempt < max_retries:
                wait = min(2 ** attempt, 30)
                log.warning("%s server error %s, retrying in %ss",
                            self.name, resp.status_code, wait)
                time.sleep(wait)
                attempt += 1
                continue

            return resp

    def get(self, url, max_retries=2, **kwargs):
        return self.request("GET", url, max_retries=max_retries, **kwargs)

    def post(self, url, max_retries=2, **kwargs):
        return self.request("POST", url, max_retries=max_retries, **kwargs)

    @abc.abstractmethod
    def enrich(self, ioc: str, ioc_type: IocType) -> SourceResult:
        ...

    def run(self, ioc, ioc_type, cache=None) -> SourceResult:
        """enrich with an optional cache in front."""
        if cache is not None:
            hit = cache.get(self.name, ioc)
            if hit is not None:
                hit["ioc_type"] = IocType(hit["ioc_type"])
                return SourceResult(**hit)

        result = self.enrich(ioc, ioc_type)

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
        )
