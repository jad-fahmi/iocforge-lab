"""Minimal STIX 2.1 Indicator bundle export."""

from datetime import datetime, timezone
from uuid import uuid4

from ioc_enricher.ioc.types import IocType

HASH_ALGORITHMS = {
    IocType.MD5: "MD5",
    IocType.SHA1: "SHA-1",
    IocType.SHA256: "SHA-256",
    IocType.SHA512: "SHA-512",
}


def export_bundle(results):
    """Export supported enrichment results as a STIX 2.1 bundle."""
    objects = [indicator_for(result) for result in results]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": [item for item in objects if item is not None],
    }


def indicator_for(result):
    """Convert one supported IOC to a STIX Indicator SDO."""
    pattern = pattern_for(result.ioc, result.ioc_type)
    if pattern is None:
        return None
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": timestamp,
        "modified": timestamp,
        "name": f"IOCForge {result.ioc_type.value}: {result.ioc}",
        "description": f"IOCForge enrichment verdict: {result.verdict}.",
        "indicator_types": ["malicious-activity" if result.verdict in {"malicious", "suspicious"} else "anomalous-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "confidence": round(max(0, min(1, result.score)) * 100),
        "labels": [f"iocforge:verdict={result.verdict}", f"iocforge:confidence={result.confidence}"],
    }


def pattern_for(ioc, ioc_type):
    """Return a STIX observation expression for an IOC type, if representable."""
    value = _escape(ioc)
    objects = {
        IocType.IPV4: "ipv4-addr:value",
        IocType.IPV6: "ipv6-addr:value",
        IocType.DOMAIN: "domain-name:value",
        IocType.URL: "url:value",
        IocType.EMAIL: "email-addr:value",
    }
    if ioc_type in HASH_ALGORITHMS:
        return f"[file:hashes.'{HASH_ALGORITHMS[ioc_type]}' = '{value}']"
    property_name = objects.get(ioc_type)
    return f"[{property_name} = '{value}']" if property_name else None


def _escape(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")
