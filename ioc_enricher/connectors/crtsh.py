"""Certificate Transparency enrichment through crt.sh."""

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://crt.sh/"


class CrtSh(Connector):
    """Find certificate names and issuer metadata for a domain without a key."""

    name = "crtsh"
    requires_api_key = False
    supported = (IocType.DOMAIN,)

    def enrich(self, ioc, ioc_type) -> SourceResult:
        try:
            response = self.get(BASE, params={"q": f"%.{ioc}", "output": "json"})
        except Exception as exc:
            log.warning("crt.sh request failed: %s", exc)
            return self._empty(ioc, ioc_type, error=str(exc))

        if response.status_code == 404:
            return self._empty(ioc, ioc_type)
        if response.status_code != 200:
            return self._empty(ioc, ioc_type, error=f"http {response.status_code}")
        try:
            return self._parse(ioc, ioc_type, response.json())
        except ValueError as exc:
            return self._empty(ioc, ioc_type, error=f"invalid provider response: {exc}")

    def _parse(self, ioc, ioc_type, payload) -> SourceResult:
        if not isinstance(payload, list) or not payload:
            return self._empty(ioc, ioc_type)
        names = sorted({
            name.lower().lstrip("*.")
            for certificate in payload[:100]
            for name in str(certificate.get("name_value", "")).splitlines()
            if name
        })[:200]
        issuers = sorted({
            certificate.get("issuer_name")
            for certificate in payload[:100]
            if certificate.get("issuer_name")
        })[:20]
        latest = max(
            (certificate.get("not_after", "") for certificate in payload[:100]),
            default=None,
        )
        return SourceResult(
            source=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            raw={
                "certificate_count": len(payload),
                "names": names,
                "issuers": issuers,
                "latest_not_after": latest,
            },
            tags=["certificate_transparency"],
            observed_at=latest,
        )
