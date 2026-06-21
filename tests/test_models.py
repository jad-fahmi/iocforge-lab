import hashlib
import json

from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult


def test_source_observation_has_stable_raw_payload_fingerprint():
    left = SourceResult(
        source="provider",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        raw={"b": 2, "a": 1},
    )
    right = SourceResult(
        source="provider",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        raw={"a": 1, "b": 2},
    )

    assert left.raw_response_sha256 == right.raw_response_sha256
    assert len(left.raw_response_sha256) == 64
    assert left.collected_at
    assert left.to_dict()["ioc_type"] == "domain"


def test_source_observation_fingerprint_changes_with_payload():
    first = SourceResult(
        source="provider",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        raw={"answer": "203.0.113.7"},
    )
    changed = SourceResult(
        source="provider",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        raw={"answer": "203.0.113.8"},
    )

    assert first.raw_response_sha256 != changed.raw_response_sha256


def test_serialization_refreshes_fingerprint_after_raw_payload_mutation():
    source = SourceResult(
        source="provider",
        ioc="example.com",
        ioc_type=IocType.DOMAIN,
        raw={"answer": "203.0.113.7"},
    )
    original_hash = source.raw_response_sha256
    source.raw["answer"] = "198.51.100.4"

    serialized = source.to_dict()
    canonical = json.dumps(
        source.raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    assert serialized["raw_response_sha256"] != original_hash
    assert serialized["raw_response_sha256"] == hashlib.sha256(canonical).hexdigest()
