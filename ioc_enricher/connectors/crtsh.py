"""Certificate Transparency enrichment through crt.sh."""

from datetime import datetime, timezone

from ioc_enricher.connectors.base import Connector, log
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

BASE = "https://crt.sh/"


class CrtSh(Connector):
    """Find certificate names and issuer metadata for a domain without a key."""

    name = "crtsh"
    version = "2"
    normalization_version = "2"
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
        certificates = [item for item in payload[:100] if isinstance(item, dict)]
        names = sorted(
            {
                name.lower().lstrip("*.")
                for certificate in certificates
                for name in str(certificate.get("name_value", "")).splitlines()
                if name
            }
        )[:200]
        issuers = sorted(
            {
                str(certificate.get("issuer_name"))
                for certificate in certificates
                if certificate.get("issuer_name")
            }
        )[:20]
        latest = max(
            (str(certificate.get("not_after") or "") for certificate in certificates),
            default=None,
        )
        related_entities = []
        for certificate in certificates:
            valid_from = _normalize_date(certificate.get("not_before"))
            valid_to = _normalize_date(certificate.get("not_after"))
            if valid_from and valid_to and valid_from > valid_to:
                continue
            certificate_id = certificate.get("id")
            certificate_node = f"certificate:crtsh:{certificate_id}"
            if certificate_id is not None:
                related_entities.append(
                    {
                        "source_ioc": ioc,
                        "target_ioc": certificate_node,
                        "relationship_type": "has_certificate",
                        "source_entity_type": "domain",
                        "target_entity_type": "certificate",
                        "valid_from": valid_from,
                        "valid_to": valid_to,
                        "attributes": {
                            "certificate_id": certificate_id,
                            "issuer_name": certificate.get("issuer_name"),
                        },
                    }
                )
            for name in str(certificate.get("name_value", "")).splitlines():
                target = name.lower().lstrip("*.").rstrip(".")
                if not target or target == ioc.lower().rstrip("."):
                    continue
                related_entities.append(
                    {
                        "source_ioc": ioc,
                        "target_ioc": target,
                        "relationship_type": "certificate_name",
                        "source_entity_type": "domain",
                        "target_entity_type": "hostname",
                        "valid_from": valid_from,
                        "valid_to": valid_to,
                        "attributes": {
                            "certificate_id": certificate.get("id"),
                            "issuer_name": certificate.get("issuer_name"),
                        },
                    }
                )
                if certificate_id is not None:
                    related_entities.append(
                        {
                            "source_ioc": certificate_node,
                            "target_ioc": target,
                            "relationship_type": "certificate_name",
                            "source_entity_type": "certificate",
                            "target_entity_type": "hostname",
                            "valid_from": valid_from,
                            "valid_to": valid_to,
                            "attributes": {
                                "certificate_id": certificate_id,
                                "issuer_name": certificate.get("issuer_name"),
                            },
                        }
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
            related_entities=related_entities,
        )


def _normalize_date(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat()
