import json

from ioc_enricher.bundles import inspect_bundle
from ioc_enricher.demo import DEMO_PAYLOAD_SHA256, DEMO_URL, main


def test_t1_t2_demo_writes_self_contained_offline_case(tmp_path, capsys):
    destination = tmp_path / "walkthrough" / "t1-t2.iocforge"

    assert main(["--output", str(destination)]) == 0

    report = json.loads(capsys.readouterr().out)
    bundle = destination.read_bytes()
    inspected = inspect_bundle(
        bundle,
        as_of=report["scenario"]["t2"],
        baseline_as_of=report["scenario"]["t1"],
        comparison_as_of=report["scenario"]["t2"],
    )
    snapshots = report["snapshots"]
    comparison = report["comparison"]

    assert [item["verdict"] for item in snapshots] == ["low", "malicious"]
    assert [item["confidence"] for item in snapshots] == ["medium", "high"]
    assert snapshots[0]["score"] < snapshots[1]["score"]
    assert snapshots[0]["counter_evidence"][0]["source"] == "virustotal"
    assert snapshots[0]["errors"] == [
        {"source": "urlhaus", "error": "HTTP 503 service unavailable"}
    ]
    assert "stale_observation" in snapshots[0]["reason_codes"]
    otx_trace = next(
        item
        for item in snapshots[0]["decision_trace"]["observations"]
        if item["source"] == "otx"
    )
    assert otx_trace["freshness_factor"] == 0.5
    assert snapshots[1]["errors"] == []
    assert all(item["replay"]["matches_original"] for item in snapshots)
    t1_paths = report["pivot_paths"]["t1"]["candidates"]
    assert DEMO_PAYLOAD_SHA256 not in {item["ioc"] for item in t1_paths}
    t2_hash_path = next(
        item
        for item in report["pivot_paths"]["t2"]["candidates"]
        if item["ioc"] == DEMO_PAYLOAD_SHA256
    )
    assert [item["entity_type"] for item in t2_hash_path["path"]] == [
        "domain",
        "url",
        "file_hash",
    ]
    assert [item["ioc"] for item in t2_hash_path["path"]] == [
        "login-update.example",
        DEMO_URL,
        DEMO_PAYLOAD_SHA256,
    ]
    assert [hop["evidence_source"] for hop in t2_hash_path["hops"]] == [
        "urlscan",
        "urlscan",
    ]
    assert comparison["verdict_changed"] is True
    assert comparison["score_delta"] > 0
    assert comparison["replay"]["baseline_matches"] is True
    assert comparison["replay"]["comparison_matches"] is True
    added_evidence = comparison["evidence_added"]
    score_contributors = {
        item["observation"]["source"]: item["decision_contribution"]
        for item in added_evidence
        if item["decision_contribution"]["included_in_aggregate"]
    }
    assert set(score_contributors) == {"virustotal", "otx", "threatfox", "urlhaus"}
    assert all(
        contribution["weighted_signal_contribution"] > 0
        for contribution in score_contributors.values()
    )
    for item in added_evidence:
        contribution = item["decision_contribution"]
        assert contribution["observation_id"] == item["id"]
        assert contribution["source"] == item["observation"]["source"]
    virustotal_change = next(
        item
        for item in comparison["provider_changes"]
        if item["source"] == "virustotal"
    )
    assert virustotal_change["baseline"][0]["observation"]["malicious"] is False
    assert virustotal_change["comparison"][0]["observation"]["malicious"] is True

    added_targets = {
        edge["target_ioc"] for edge in comparison["graph"]["added_edges"]
    }
    removed_targets = {
        edge["target_ioc"] for edge in comparison["graph"]["removed_edges"]
    }
    assert "198.51.100.27" in added_targets
    assert "certificate:crtsh:991" in added_targets
    assert DEMO_URL in added_targets
    assert DEMO_PAYLOAD_SHA256 in added_targets
    assert "203.0.113.42" in removed_targets
    assert inspected["snapshot_count"] == 2
    assert inspected["event_integrity"]["investigation"]["valid"] is True
    assert all(result["matches_original"] for result in inspected["replay"])
    offline_investigation = inspected["investigation_replay"]
    assert offline_investigation["replayable"] is True
    assert DEMO_PAYLOAD_SHA256 in {
        edge["target_ioc"] for edge in offline_investigation["graph"]["edges"]
    }
    offline_investigation_diff = inspected["investigation_comparison"]
    assert offline_investigation_diff["replayable"] is True
    assert DEMO_PAYLOAD_SHA256 in {
        edge["target_ioc"]
        for edge in offline_investigation_diff["graph"]["added_edges"]
    }
    assert DEMO_URL in {
        edge["target_ioc"]
        for edge in offline_investigation_diff["graph"]["added_edges"]
    }
    assert len(inspected["comparisons"]) == 1
    offline_comparison = inspected["comparisons"][0]
    assert offline_comparison["verdict_changed"] is True
    assert offline_comparison["replay"]["baseline"]["matches_original"] is True
    assert offline_comparison["replay"]["comparison"]["matches_original"] is True
    assert "198.51.100.27" in {
        edge["target_ioc"] for edge in offline_comparison["graph"]["added_edges"]
    }
