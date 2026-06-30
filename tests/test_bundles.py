import copy
import io
import json
import zipfile
from datetime import datetime, timezone

import ioc_enricher.history as history_module
import ioc_enricher.scoring as scoring_module
import pytest
from ioc_enricher.bundles import build_bundle, inspect_bundle
from ioc_enricher.history import HistoryStore, _observation_key
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import score


def _bundle_payload(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    result = EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN)
    result.unavailable_providers = [
        {
            "source": "virustotal",
            "state": "unavailable",
            "reason": "required_credentials_missing",
        }
    ]
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


def test_large_investigation_bundle_keeps_all_members_and_bounds_graph(tmp_path):
    store = HistoryStore(tmp_path / "large-bundle.db")
    investigation = store.create_investigation("Large investigation")
    iocs = [f"bundle-{index:04d}.example" for index in range(501)]
    for ioc in iocs:
        store.add_investigation_indicator(investigation["id"], ioc)

    statements = []
    store.conn.set_trace_callback(statements.append)
    payload = store.investigation_bundle_payload(investigation["id"])
    store.close()

    assert payload is not None
    assert payload["investigation"]["indicators"] == iocs
    root_lookup_prefix = (
        "SELECT id, entity_type, canonical_value FROM graph_entities "
        "WHERE entity_type"
    )
    assert sum(
        statement.startswith(root_lookup_prefix)
        for statement in statements
    ) == 2
    assert payload["graph"]["edge_limit"] == 500
    assert len(payload["graph"]["edges"]) == 500
    assert payload["graph"]["truncated"] is True


def test_bundle_capture_traverses_shared_member_graph_together(tmp_path, monkeypatch):
    store = HistoryStore(tmp_path / "shared-bundle.db")
    investigation = store.create_investigation("Shared infrastructure")
    iocs = [f"shared-{index:03d}.example" for index in range(100)]
    for index, ioc in enumerate(iocs):
        store.add_investigation_indicator(investigation["id"], ioc)
        store.add_relationship(
            ioc,
            f"198.51.100.{index + 1}",
            "resolves_to",
            confidence=0.8,
            evidence_source="analyst",
        )

    relationship_queries = 0
    original_query = store._relationships_for_entities

    def count_relationship_queries(*args, **kwargs):
        nonlocal relationship_queries
        relationship_queries += 1
        return original_query(*args, **kwargs)

    monkeypatch.setattr(store, "_relationships_for_entities", count_relationship_queries)
    payload = store.investigation_bundle_payload(investigation["id"])
    store.close()

    assert payload is not None
    assert len(payload["graph"]["edges"]) == 200
    assert payload["graph"]["truncated"] is False
    assert relationship_queries < len(iocs)


def test_bundle_reconstructs_and_compares_investigation_offline(tmp_path, monkeypatch):
    class Clock(datetime):
        current = datetime(2026, 1, 1, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)

    monkeypatch.setattr(history_module, "datetime", Clock)
    store = HistoryStore(tmp_path / "temporal.db")
    t1 = "2026-01-01T00:00:00+00:00"
    t2 = "2026-01-03T00:00:00+00:00"
    investigation = store.create_investigation("T1 bundle case", "Original")
    store.add_investigation_indicator(investigation["id"], "evil.example")
    first = EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN)
    first.add(
        SourceResult(
            source="passive_dns",
            ioc="evil.example",
            ioc_type=IocType.DOMAIN,
            found=True,
            malicious=True,
            score=0.9,
            observed_at=t1,
            collected_at=t1,
            raw={"answer": "203.0.113.10"},
            related_entities=[
                {
                    "source_ioc": "evil.example",
                    "target_ioc": "203.0.113.10",
                    "relationship_type": "resolves_to",
                    "confidence": 0.9,
                    "valid_from": t1,
                }
            ],
        )
    )
    score(first, as_of=t1)
    store.record(first, looked_up_at=t1)
    store.set_verdict_override("evil.example", "suspicious", "Review pending")

    Clock.current = datetime(2026, 1, 3, tzinfo=timezone.utc)
    second = EnrichmentResult(ioc="evil.example", ioc_type=IocType.DOMAIN)
    second.add(
        SourceResult(
            source="passive_dns",
            ioc="evil.example",
            ioc_type=IocType.DOMAIN,
            found=True,
            malicious=False,
            score=0.0,
            observed_at=t2,
            collected_at=t2,
            raw={"answer": "198.51.100.20"},
            related_entities=[
                {
                    "source_ioc": "evil.example",
                    "target_ioc": "198.51.100.20",
                    "relationship_type": "resolves_to",
                    "confidence": 0.95,
                    "valid_from": t2,
                }
            ],
        )
    )
    score(second, as_of=t2)
    store.record(second, looked_up_at=t2)
    store.add_investigation_indicator(investigation["id"], "new.example")
    store.update_investigation(
        investigation["id"], description="Updated", status="closed"
    )
    store.clear_verdict_override("evil.example")
    payload = store.investigation_bundle_payload(investigation["id"])
    store.close()
    assert payload is not None

    report = inspect_bundle(
        build_bundle(payload),
        as_of="2026-01-02T00:00:00Z",
        baseline_as_of="2026-01-02T00:00:00Z",
        comparison_as_of=t2,
    )
    replay = report["investigation_replay"]
    comparison = report["investigation_comparison"]

    assert replay["state_complete"] is True
    assert replay["replayable"] is True
    assert replay["indicator_count"] == 1
    assert replay["investigation"]["description"] == "Original"
    assert replay["indicators"][0]["analyst_state"]["verdict_override"] == "suspicious"
    assert replay["indicators"][0]["latest_enrichment"]["source_verdict"] == "malicious"
    assert comparison["membership"]["added"] == ["new.example"]
    evil = next(item for item in comparison["indicators"] if item["ioc"] == "evil.example")
    assert evil["decision"]["baseline_verdict"] == "malicious"
    assert evil["decision"]["comparison_verdict"] == "clean"
    assert evil["evidence"]["added"]
    assert evil["analyst_state_changed"] is True
    assert any(
        edge["target_ioc"] == "198.51.100.20"
        for edge in comparison["graph"]["added_edges"]
    )


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


def test_offline_bundle_replay_uses_saved_scoring_version(tmp_path, monkeypatch):
    payload = _bundle_payload(tmp_path)
    monkeypatch.setattr(scoring_module, "METHODOLOGY_VERSION", "3")

    report = inspect_bundle(build_bundle(payload))

    assert report["replay"]
    assert all(item["replayable"] for item in report["replay"])
    assert all(item["matches_original"] for item in report["replay"])


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        (
            "collected_at",
            "2026-01-02T00:00:00+00:00",
            "evidence_collected_after_snapshot",
        ),
        ("observed_at", "yesterday, probably", "evidence_timestamps_invalid"),
    ],
)
def test_offline_bundle_replay_rejects_inconsistent_evidence_times(
    tmp_path, field, value, expected_reason
):
    payload = _bundle_payload(tmp_path)
    snapshot = payload["snapshots"][0]
    linked = snapshot["observations"][0]
    indexed = next(item for item in payload["observations"] if item["id"] == linked["id"])
    for evidence in (linked["observation"], indexed["observation"]):
        evidence[field] = value
    snapshot["result"]["sources"][0][field] = value
    if field == "collected_at":
        observation_key = _observation_key(linked["observation"])
        linked["observation_key"] = observation_key
        indexed["observation_key"] = observation_key
    report = inspect_bundle(build_bundle(payload), as_of="2026-01-02T00:00:00Z")

    assert report["replay"][0]["replayable"] is False
    assert report["replay"][0]["reason"] == expected_reason
    assert report["investigation_replay"]["replayable"] is False


def test_bundle_rejects_snapshot_evidence_index_mismatch(tmp_path):
    payload = _bundle_payload(tmp_path)
    payload["observations"] = copy.deepcopy(payload["observations"])
    payload["snapshots"][0]["observations"][0]["observation"]["malicious"] = False

    with pytest.raises(ValueError, match="does not match evidence index"):
        inspect_bundle(build_bundle(payload))


def test_bundle_rejects_snapshot_source_evidence_mismatch(tmp_path):
    payload = _bundle_payload(tmp_path)
    payload["snapshots"][0]["result"]["sources"][0]["malicious"] = False

    with pytest.raises(ValueError, match="source does not match linked evidence"):
        inspect_bundle(build_bundle(payload))


def test_bundle_rejects_graph_edges_with_missing_evidence_references(tmp_path):
    payload = _bundle_payload(tmp_path)
    payload["graph"]["edges"][0]["evidence_observation_id"] = 999

    with pytest.raises(ValueError, match="graph evidence reference is missing"):
        inspect_bundle(build_bundle(payload))


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
