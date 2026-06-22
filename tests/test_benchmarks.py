from benchmarks.run_benchmarks import run_benchmarks


def test_benchmark_smoke_measures_persistence_graph_scheduler_and_replay():
    report = run_benchmarks(
        indicators=4,
        lookup_workers=2,
        scheduler_concurrency=2,
        max_pending=4,
        provider_delay_ms=0,
        replay_samples=2,
    )

    assert report["methodology"] == "iocforge-local-benchmark-v1"
    assert report["offline_enrichment"]["results"] == 4
    assert report["offline_enrichment"]["scheduler"]["max_active_tasks"] <= 2
    assert report["scheduler_with_history"]["scheduler"]["max_active_tasks"] <= 2
    assert report["replay"]["total_samples"] == 2
    assert report["graph"]["pivots_returned"] >= 1
    assert report["storage"]["rows"]["enrichments"] == 4
    assert report["storage"]["rows"]["evidence_observations"] == 8
    assert report["storage"]["rows"]["indicator_relationships"] == 8
    assert report["storage"]["growth_bytes"] > 0
    assert report["storage"]["growth_bytes_per_indicator"] > 0
