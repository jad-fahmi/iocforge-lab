from ioc_enricher.connectors.base import Connector
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(Connector):
    name = "virustotal"
    supported = (
        IocType.IPV4,
        IocType.IPV6,
        IocType.DOMAIN,
        IocType.URL,
        IocType.MD5,
        IocType.SHA1,
        IocType.SHA256,
    )

    def _path(self, ioc, ioc_type):
        if ioc_type in (IocType.IPV4, IocType.IPV6):
            return f"/ip_addresses/{ioc}"
        if ioc_type == IocType.DOMAIN:
            return f"/domains/{ioc}"
        if ioc_type.is_hash():
            return f"/files/{ioc}"
        # url handling comes later
        return None

    def enrich(self, ioc, ioc_type) -> SourceResult:
        path = self._path(ioc, ioc_type)
        print("vt path:", path)  # debugging
        if path is None:
            return self._empty(ioc, ioc_type, error="unsupported for vt yet")

        # TODO actually call the api
        return self._empty(ioc, ioc_type, error="not implemented")
