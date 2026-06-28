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

    def get(self, url, max_retries=2, **kwargs):
        """wrapper that backs off once on a 429."""
        attempt = 0
        while True:
            resp = self.client.get(url, **kwargs)
            if resp.status_code != 429 or attempt >= max_retries:
                return resp
            wait = float(resp.headers.get("Retry-After", 2))
            log.warning("%s rate limited, sleeping %ss", self.name, wait)
            time.sleep(min(wait, 30))
            attempt += 1

    @abc.abstractmethod
    def enrich(self, ioc: str, ioc_type: IocType) -> SourceResult:
        ...

    def _empty(self, ioc, ioc_type, error=None):
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=error,
        )
