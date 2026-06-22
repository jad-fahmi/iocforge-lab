import io
import json
import zipfile

import pytest
from ioc_enricher.bundles import build_bundle, inspect_bundle
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import score


def _bundle_payload(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN)
    result.add(
        SourceResult(
            source="passive_dns",
            ioc="evil.example",
            ioc_type=IocType.DOMAIN,
            found=True,
            malicious=True,
            score=0.9,
            raw={"answer": "203.0.113.10"},
            collected_at="2026-01-01T00:00:00+00:00",
            related_entities=[
                {
                    "source_ioc": "evil.example",
                    "target_ioc": "203.0.113.10",
                    "relationship_type": "resolves_to",
                    "confidence": 0.9,
                    "observed_at": "2026-01-01T00:00:00+00:00",
                }
            ],
        )
    )
    score(result, as_of="2026-01-01T00:00:00+00:00")
    store.record(result, "2026-01-01T00:00:00+00:00")
    investigation = store.create_investigation("Phishing triage")
    store.add_investigation_indicator(investigation["id"], "evil.example")
    payload = store.investigation_bundle_payload(investigation["id"])
    store.close()
    assert payload is not None
    return payload


def test_investigation_bundle_replays_without_providers_and_includes_graph(tmp_path):
    report = inspect_bundle(build_bundle(_bundle_payload(tmp_path)))

    assert report["investigation"]["title"] == "Phishing triage"
    assert report["snapshot_count"] == 1
    assert report["observation_count"] == 1
    assert report["graph"]["edges"][0]["target_ioc"] == "203.0.113.10"
    assert report["event_integrity"]["investigation"]["valid"] is True
    assert report["event_integrity"]["indicators"]["evil.example"]["valid"] is True
    assert report["comparisons"] == []
    assert report["replay"] == [
        {
            "enrichment_id": 1,
            "replayable": True,
            "matches_original": True,
            "scoring_version": "2",
            "scored_at": "2026-01-01T00:00:00+00:00",
        }
    ]


def test_bundle_checksum_detects_modified_payload(tmp_path):
    bundle_bytes = build_bundle(_bundle_payload(tmp_path))
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as archive:
        document = json.loads(archive.read("bundle.json"))
    document["payload"]["investigation"]["title"] = "changed"
    altered = io.BytesIO()
    with zipfile.ZipFile(altered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bundle.json", json.dumps(document))

    with pytest.raises(ValueError, match="checksum"):
        inspect_bundle(altered.getvalue())


def test_bundle_raw_observation_hash_is_independently_checked(tmp_path):
    payload = _bundle_payload(tmp_path)
    payload["observations"][0]["observation"]["raw"]["answer"] = "198.51.100.2"
    bundle = build_bundle(payload)

    with pytest.raises(ValueError, match="raw observation hash"):
        inspect_bundle(bundle)


def test_bundle_rejects_extra_archive_members(tmp_path):
    bundle_bytes = build_bundle(_bundle_payload(tmp_path))
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as archive:
        document = archive.read("bundle.json")
    altered = io.BytesIO()
    with zipfile.ZipFile(altered, "w") as archive:
        archive.writestr("bundle.json", document)
        archive.writestr("../unexpected.txt", "not extracted")

    with pytest.raises(ValueError, match="only bundle.json"):
        inspect_bundle(altered.getvalue())


def test_bundle_rejects_malformed_temporal_graph_edges(tmp_path):
    payload = _bundle_payload(tmp_path)
    payload["graph"]["edges"][0]["target_entity_id"] = "not-an-entity-id"

    with pytest.raises(ValueError, match="graph edge is invalid"):
        inspect_bundle(build_bundle(payload))
