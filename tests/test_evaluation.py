import copy
from pathlib import Path

import pytest
from ioc_enricher.evaluation import evaluate_fixture, load_fixture

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "provider-evaluation-v1.json"


def test_provider_evaluation_metrics_are_reproducible_and_cover_failure_modes():
    fixture = load_fixture(FIXTURE_PATH)

    first = evaluate_fixture(fixture)
    second = evaluate_fixture(fixture)

    assert first == second
    assert first["case_count"] == 4
    assert len(first["dataset_sha256"]) == 64
    alpha = first["providers"]["alpha"]
    beta = first["providers"]["beta"]
    assert alpha["coverage"] == 0.75
    coverage_interval = alpha["coverage_interval_95"]
    assert coverage_interval["method"] == "wilson_score"
    assert coverage_interval["successes"] == 3
    assert coverage_interval["trials"] == 4
    assert coverage_interval["lower"] < alpha["coverage"] < coverage_interval["upper"]
    assert alpha["failure_rate"] == 0.25
    assert alpha["latency_ms"] == {
        "sample_count": 4,
        "mean": 57.625,
        "p50": 20.0,
        "p95": 120.5,
    }
    assert alpha["classification"]["false_positive"] == 1
    assert alpha["classification"]["false_negative"] == 0
    precision_interval = alpha["classification"]["wilson_intervals_95"]["precision"]
    assert precision_interval["successes"] == 1
    assert precision_interval["trials"] == 2
    assert precision_interval["lower"] < 0.5 < precision_interval["upper"]
    assert beta["classification"]["false_negative"] == 1
    assert beta["freshness_age_seconds"]["future_timestamp_count"] == 1
    assert first["disagreement"]["rate"] == 0.5
    assert first["positive_overlap"][0]["jaccard"] == 0.0
    assert "not be treated as production" in first["reliability_note"]


def test_provider_evaluation_omits_unmeasurable_classification_intervals():
    result = evaluate_fixture(
        {
            "schema_version": 1,
            "providers": ["provider"],
            "cases": [
                {
                    "id": "unknown-truth",
                    "ioc": "unknown.example",
                    "truth": {"malicious": None},
                    "sources": [
                        {
                            "source": "provider",
                            "found": True,
                            "malicious": True,
                        }
                    ],
                }
            ],
        }
    )

    metrics = result["providers"]["provider"]
    assert metrics["coverage_interval_95"]["trials"] == 1
    assert metrics["classification"]["labelled_count"] == 0
    assert metrics["classification"]["wilson_intervals_95"] == {
        "precision": None,
        "recall": None,
        "specificity": None,
    }


def test_cache_hits_are_excluded_from_provider_latency_samples():
    fixture = load_fixture(FIXTURE_PATH)
    cached = copy.deepcopy(fixture)
    cached["cases"][3]["sources"][1]["cache_hit"] = True

    result = evaluate_fixture(cached)

    assert result["providers"]["beta"]["latency_ms"]["sample_count"] == 3


@pytest.mark.parametrize(
    "mutate",
    [
        lambda fixture: fixture.update(schema_version=2),
        lambda fixture: fixture["cases"][0].update(as_of="yesterday"),
        lambda fixture: fixture["cases"][0]["sources"][0].update(latency_ms=-1),
        lambda fixture: fixture["cases"][0]["sources"][0].update(malicious="yes"),
    ],
)
def test_provider_evaluation_rejects_invalid_fixture_inputs(mutate):
    fixture = load_fixture(FIXTURE_PATH)
    mutate(fixture)

    with pytest.raises(ValueError):
        evaluate_fixture(fixture)
