"""Direct DNS resolution enrichment for domain indicators."""

import dns.exception
import dns.resolver

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult


class DNS(Connector):
    """Resolve A, AAAA, CNAME, MX, and NS records without an API key."""

    name = "dns"
    requires_api_key = False
    supported = (IocType.DOMAIN,)
    record_types = ("A", "AAAA", "CNAME", "MX", "NS")

    def enrich(self, ioc, ioc_type) -> SourceResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        records: dict[str, list[str]] = {}
        try:
            for record_type in self.record_types:
                try:
                    answer = resolver.resolve(ioc, record_type)
                    records[record_type] = [
                        str(record).rstrip(".") for record in answer
                    ]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
        except dns.exception.DNSException as exc:
            log.warning("DNS resolution failed for %s: %s", ioc, exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if not records:
            return self._empty(ioc, ioc_type)
        tags = [f"dns:{record_type.lower()}" for record_type in records]
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw={"records": records},
            tags=tags,
        )
