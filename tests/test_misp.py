from ioc_enricher.interoperability.misp import export_event, import_event
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult


def test_misp_export_maps_iocs_and_preserves_unpublished_default():
    result = EnrichmentResult(
        ioc="evil.example", ioc_type=IocType.DOMAIN, verdict="malicious", score=0.9,
        confidence="high",
    )

    event = export_event([result], info="Triage export")["Event"]

    assert event["info"] == "Triage export"
    assert event["published"] is False
    assert event["threat_level_id"] == "1"
    assert event["Attribute"] == [{
        "type": "domain", "category": "Network activity", "value": "evil.example",
        "to_ids": True, "distribution": "0",
        "comment": "IOCForge verdict=malicious; score=0.9; confidence=high",
    }]


def test_misp_import_extracts_only_supported_valid_attributes():
    indicators = import_event({"Event": {"Attribute": [
        {"type": "domain", "value": "EVIL.EXAMPLE", "to_ids": True},
        {"type": "domain", "value": "not a domain"},
        {"type": "text", "value": "ignore me"},
    ]}})

    assert indicators == [{"ioc": "evil.example", "ioc_type": "domain", "misp_type": "domain", "to_ids": True}]
