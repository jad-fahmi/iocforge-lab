"""Deliberately small, safe STIX 2.1 Indicator import and export support."""

import re
from datetime import datetime, timezone
from uuid import uuid4

from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.ioc.types import IocType

HASH_ALGORITHMS = {
    IocType.MD5: "MD5",
    IocType.SHA1: "SHA-1",
    IocType.SHA256: "SHA-256",
    IocType.SHA512: "SHA-512",
}

OBSERVABLE_TYPES = {
    "ipv4-addr:value": IocType.IPV4,
    "ipv6-addr:value": IocType.IPV6,
    "domain-name:value": IocType.DOMAIN,
    "url:value": IocType.URL,
    "email-addr:value": IocType.EMAIL,
}
PATTERN_RE = re.compile(
    r"^\[(?P<observable>ipv4-addr:value|ipv6-addr:value|domain-name:value|"
    r"url:value|email-addr:value|file:hashes\.'(?P<hash>MD5|SHA-1|SHA-256|SHA-512)')"
    r"\s*=\s*'(?P<value>(?:\\.|[^'])*)'\]$"
)


def export_bundle(results):
    """Export supported enrichment results as a STIX 2.1 bundle."""
    objects = [indicator_for(result) for result in results]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": [item for item in objects if item is not None],
    }


def import_bundle(bundle):
    """Extract validated IOCs from simple STIX 2.1 Indicator patterns.

    This intentionally accepts only the exact observation expressions emitted by
    :func:`pattern_for`; it does not evaluate arbitrary STIX pattern language.
    """
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("expected a STIX bundle")
    imported = []
    seen = set()
    for item in bundle.get("objects", []):
        if not isinstance(item, dict) or item.get("type") != "indicator":
            continue
        parsed = _parse_pattern(item.get("pattern"))
        if parsed is None or parsed[0] in seen:
            continue
        ioc, ioc_type = parsed
        seen.add(ioc)
        labels = item.get("labels")
        imported.append(
            {
                "ioc": ioc,
                "ioc_type": ioc_type.value,
                "stix_id": item.get("id"),
                "labels": [label for label in labels if isinstance(label, str)]
                if isinstance(labels, list)
                else [],
            }
        )
    return imported


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
        "indicator_types": [
            "malicious-activity"
            if result.verdict in {"malicious", "suspicious"}
            else "anomalous-activity"
        ],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "confidence": round(max(0, min(1, result.score)) * 100),
        "labels": [
            f"iocforge:verdict={result.verdict}",
            f"iocforge:confidence={result.confidence}",
        ],
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


def _parse_pattern(pattern):
    if not isinstance(pattern, str):
        return None
    match = PATTERN_RE.fullmatch(pattern)
    if match is None:
        return None
    ioc_type = (
        HASH_ALGORITHMS_INV.get(match.group("hash"))
        if match.group("hash")
        else OBSERVABLE_TYPES[match.group("observable")]
    )
    value = match.group("value").replace("\\'", "'").replace("\\\\", "\\")
    if detect(value) != ioc_type:
        return None
    return normalize(value, ioc_type), ioc_type


HASH_ALGORITHMS_INV = {
    algorithm: ioc_type for ioc_type, algorithm in HASH_ALGORITHMS.items()
}
