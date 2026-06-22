import json

from ioc_enricher.bundles import inspect_bundle
from ioc_enricher.demo import main


def test_t1_t2_demo_writes_self_contained_offline_case(tmp_path, capsys):
    destination = tmp_path / "walkthrough" / "t1-t2.iocforge"

    assert main(["--output", str(destination)]) == 0

    report = json.loads(capsys.readouterr().out)
    bundle = destination.read_bytes()
    inspected = inspect_bundle(bundle)
    snapshots = report["snapshots"]
    comparison = report["comparison"]

    assert [item["verdict"] for item in snapshots] == ["clean", "malicious"]
    assert snapshots[0]["score"] < snapshots[1]["score"]
    assert all(item["replay"]["matches_original"] for item in snapshots)
    assert comparison["verdict_changed"] is True
    assert comparison["score_delta"] > 0
    assert comparison["replay"]["baseline_matches"] is True
    assert comparison["replay"]["comparison_matches"] is True

    added_targets = {
        edge["target_ioc"] for edge in comparison["graph"]["added_edges"]
    }
    removed_targets = {
        edge["target_ioc"] for edge in comparison["graph"]["removed_edges"]
    }
    assert "198.51.100.27" in added_targets
    assert "certificate:crtsh:991" in added_targets
    assert "203.0.113.42" in removed_targets
    assert inspected["snapshot_count"] == 2
    assert inspected["event_integrity"]["investigation"]["valid"] is True
    assert all(result["matches_original"] for result in inspected["replay"])
    assert len(inspected["comparisons"]) == 1
    offline_comparison = inspected["comparisons"][0]
    assert offline_comparison["verdict_changed"] is True
    assert offline_comparison["replay"]["baseline"]["matches_original"] is True
    assert offline_comparison["replay"]["comparison"]["matches_original"] is True
    assert "198.51.100.27" in {
        edge["target_ioc"] for edge in offline_comparison["graph"]["added_edges"]
    }
