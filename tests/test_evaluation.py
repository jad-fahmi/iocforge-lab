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
    assert alpha["classification"]["reliability_weight_candidate"] == {
        "method": "clamped_youden_j_v1",
        "value": 0.5,
        "labelled_count": 3,
        "positive_count": 1,
        "negative_count": 2,
    }
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
    assert metrics["classification"]["reliability_weight_candidate"]["value"] is None


def test_reliability_weight_candidate_clamps_inverted_predictions_to_zero():
    fixture = {
        "schema_version": 1,
        "providers": ["provider"],
        "cases": [
            {
                "id": f"case-{index}",
                "ioc": f"case-{index}.example",
                "truth": {"malicious": index < 2},
                "sources": [
                    {
                        "source": "provider",
                        "found": True,
                        "malicious": index >= 2,
                    }
                ],
            }
            for index in range(4)
        ],
    }

    result = evaluate_fixture(fixture)

    candidate = result["providers"]["provider"]["classification"][
        "reliability_weight_candidate"
    ]
    assert candidate["value"] == 0.0
    assert candidate["labelled_count"] == 4


def test_detection_miss_rate_counts_successful_no_data_separately_from_classification():
    fixture = {
        "schema_version": 1,
        "providers": ["provider"],
        "cases": [
            {
                "id": "malicious-no-data",
                "ioc": "no-data.example",
                "truth": {"malicious": True},
                "sources": [
                    {"source": "provider", "found": False, "malicious": None}
                ],
            },
            {
                "id": "malicious-clean-verdict",
                "ioc": "clean-verdict.example",
                "truth": {"malicious": True},
                "sources": [
                    {"source": "provider", "found": True, "malicious": False}
                ],
            },
            {
                "id": "malicious-outage",
                "ioc": "outage.example",
                "truth": {"malicious": True},
                "sources": [
                    {
                        "source": "provider",
                        "found": False,
                        "malicious": None,
                        "error": "provider timeout",
                    }
                ],
            },
            {
                "id": "malicious-not-attempted",
                "ioc": "not-attempted.example",
                "truth": {"malicious": True},
                "sources": [],
            },
            {
                "id": "benign-clean-verdict",
                "ioc": "benign.example",
                "truth": {"malicious": False},
                "sources": [
                    {"source": "provider", "found": True, "malicious": False}
                ],
            },
        ],
    }

    result = evaluate_fixture(fixture)

    metrics = result["providers"]["provider"]
    assert metrics["detection"] == {
        "expected_malicious_count": 4,
        "attempted_malicious_count": 2,
        "missed_malicious_count": 1,
        "miss_rate": 0.5,
        "miss_rate_interval_95": {
            "method": "wilson_score",
            "confidence_level": 0.95,
            "successes": 1,
            "trials": 2,
            "lower": 0.0945,
            "upper": 0.9055,
        },
    }
    assert metrics["classification"]["false_negative"] == 1
    assert metrics["failure_count"] == 1
    assert metrics["not_attempted_count"] == 1


def test_cache_hits_are_excluded_from_provider_latency_samples():
    fixture = load_fixture(FIXTURE_PATH)
    cached = copy.deepcopy(fixture)
    cached["cases"][3]["sources"][1]["cache_hit"] = True

    result = evaluate_fixture(cached)

    assert result["providers"]["beta"]["latency_ms"]["sample_count"] == 3


def test_positive_overlap_uses_canonical_indicator_identity():
    result = evaluate_fixture(
        {
            "schema_version": 1,
            "providers": ["alpha", "beta"],
            "cases": [
                {
                    "id": "unicode-domain",
                    "ioc": "faß.de",
                    "sources": [
                        {"source": "alpha", "found": True, "malicious": True}
                    ],
                },
                {
                    "id": "idna-domain",
                    "ioc": "XN--FA-HIA.DE",
                    "sources": [
                        {"source": "beta", "found": True, "malicious": True}
                    ],
                },
                {
                    "id": "different-ascii-domain",
                    "ioc": "fass.de",
                    "sources": [
                        {"source": "beta", "found": True, "malicious": True}
                    ],
                },
            ],
        }
    )

    overlap = result["positive_overlap"][0]
    assert result["ioc_normalization_version"] == "2"
    assert overlap["intersection_count"] == 1
    assert overlap["union_count"] == 2
    assert overlap["jaccard"] == 0.5


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
