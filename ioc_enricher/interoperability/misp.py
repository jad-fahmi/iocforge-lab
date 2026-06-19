"""MISP event JSON export for IOCForge enrichment results."""

from datetime import datetime, timezone

from ioc_enricher.ioc.types import IocType

MISP_TYPES = {
    IocType.IPV4: ("ip-dst", "Network activity"),
    IocType.IPV6: ("ip-dst", "Network activity"),
    IocType.DOMAIN: ("domain", "Network activity"),
    IocType.URL: ("url", "Network activity"),
    IocType.EMAIL: ("email-dst", "Payload delivery"),
    IocType.MD5: ("md5", "Payload delivery"),
    IocType.SHA1: ("sha1", "Payload delivery"),
    IocType.SHA256: ("sha256", "Payload delivery"),
    IocType.SHA512: ("sha512", "Payload delivery"),
    IocType.CVE: ("vulnerability", "External analysis"),
    IocType.ASN: ("AS", "Network activity"),
}


def export_event(results, info="IOCForge enrichment export"):
    """Return MISP-compatible event JSON without publishing to a server."""
    attributes = [attribute_for(result) for result in results]
    usable = [attribute for attribute in attributes if attribute is not None]
    verdicts = {result.verdict for result in results}
    threat_level = 1 if "malicious" in verdicts else 2 if "suspicious" in verdicts else 3
    return {
        "Event": {
            "date": datetime.now(timezone.utc).date().isoformat(),
            "info": info,
            "published": False,
            "analysis": "1",
            "distribution": "0",
            "threat_level_id": str(threat_level),
            "Attribute": usable,
        }
    }


def attribute_for(result):
    """Map one IOC enrichment result to a MISP attribute."""
    mapping = MISP_TYPES.get(result.ioc_type)
    if mapping is None:
        return None
    attribute_type, category = mapping
    actionable = result.verdict in {"malicious", "suspicious"}
    return {
        "type": attribute_type,
        "category": category,
        "value": result.ioc,
        "to_ids": actionable,
        "distribution": "0",
        "comment": (
            f"IOCForge verdict={result.verdict}; score={result.score}; "
            f"confidence={result.confidence}"
        ),
    }
