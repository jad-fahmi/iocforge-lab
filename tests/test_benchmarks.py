from benchmarks.run_benchmarks import run_benchmark_series, run_benchmarks


def test_benchmark_smoke_measures_persistence_graph_scheduler_and_replay():
    report = run_benchmarks(
        indicators=4,
        lookup_workers=2,
        scheduler_concurrency=2,
        max_pending=4,
        provider_delay_ms=0,
        replay_samples=2,
    )

    assert report["methodology"] == "iocforge-local-benchmark-v2"
    assert report["offline_enrichment"]["results"] == 4
    assert report["offline_enrichment"]["scheduler"]["max_active_tasks"] <= 2
    assert report["scheduler_with_history"]["scheduler"]["max_active_tasks"] <= 2
    assert report["replay"]["total_samples"] == 2
    assert report["graph"]["pivots_returned"] >= 1
    assert report["graph"]["pivot_paths_returned"] >= 1
    assert report["graph"]["pivot_path_expansions"] <= 5000
    assert report["graph"]["pivot_path_truncated"] is False
    assert report["storage"]["rows"]["enrichments"] == 4
    assert report["storage"]["rows"]["evidence_observations"] == 8
    assert report["storage"]["rows"]["indicator_relationships"] == 10
    assert report["storage"]["growth_bytes"] > 0
    assert report["storage"]["growth_bytes_per_indicator"] > 0


def test_benchmark_series_summarizes_reproducible_repeated_runs():
    report = run_benchmark_series(
        repeats=2,
        warmup_runs=1,
        indicators=3,
        lookup_workers=2,
        scheduler_concurrency=2,
        max_pending=4,
        provider_delay_ms=0,
        replay_samples=1,
    )

    assert report["methodology"] == "iocforge-benchmark-series-v1"
    assert report["benchmark_methodology"] == "iocforge-local-benchmark-v2"
    assert report["warmup_runs"] == 1
    assert report["measured_runs"] == 2
    assert len(report["samples"]) == 2
    assert {sample["workload_sha256"] for sample in report["samples"]} == {
        report["workload_sha256"]
    }
    throughput = report["summary"]["scheduler_with_history_indicators_per_second"]
    assert throughput["sample_count"] == 2
    assert throughput["min"] <= throughput["median"] <= throughput["max"]
