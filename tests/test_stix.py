from ioc_enricher.interoperability.stix import export_bundle, import_bundle, pattern_for
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult


def test_stix_patterns_cover_network_and_hash_iocs():
    assert pattern_for("198.51.100.1", IocType.IPV4) == "[ipv4-addr:value = '198.51.100.1']"
    assert pattern_for("a" * 64, IocType.SHA256) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"


def test_stix_bundle_exports_supported_types_only():
    supported = EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN, verdict="malicious", score=0.9)
    unsupported = EnrichmentResult(ioc="CVE-2026-1", ioc_type=IocType.CVE)

    bundle = export_bundle([supported, unsupported])

    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["spec_version"] == "2.1"
    assert bundle["objects"][0]["pattern"] == "[domain-name:value = 'evil.example']"


def test_stix_import_extracts_only_valid_simple_indicator_patterns():
    indicators = import_bundle(
        {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'EVIL.EXAMPLE']", "labels": ["phishing"]},
                {"type": "indicator", "pattern": "[domain-name:value = 'a'] OR [domain-name:value = 'b']"},
            ],
        }
    )

    assert indicators == [{"ioc": "evil.example", "ioc_type": "domain", "stix_id": "indicator--1", "labels": ["phishing"]}]
