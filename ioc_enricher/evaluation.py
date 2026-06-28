"""Deterministic offline provider evaluation over labeled fixtures."""

import hashlib
import json
import math
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any

from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.detect import (
    IOC_NORMALIZATION_VERSION,
    detect,
    normalize,
)
from ioc_enricher.ioc.types import IocType

EVALUATION_SCHEMA_VERSION = 1
EVALUATION_METHODOLOGY = "iocforge-provider-evaluation-v4"
MAX_EVALUATION_FIXTURE_BYTES = 10 * 1024 * 1024
WILSON_95_Z = 1.959963984540054


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _wilson_interval(successes: int, trials: int) -> dict[str, Any] | None:
    """Return the two-sided 95% Wilson score interval for one binomial rate."""
    if trials <= 0:
        return None
    z_squared = WILSON_95_Z**2
    observed = successes / trials
    denominator = 1 + z_squared / trials
    center = (observed + z_squared / (2 * trials)) / denominator
    margin = (
        WILSON_95_Z
        * math.sqrt(
            observed * (1 - observed) / trials
            + z_squared / (4 * trials**2)
        )
        / denominator
    )
    return {
        "confidence_level": 0.95,
        "successes": successes,
        "trials": trials,
        "lower": round(max(0.0, center - margin), 4),
        "upper": round(min(1.0, center + margin), 4),
        "method": "wilson_score",
    }


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def _canonical_ioc(value: str) -> str:
    """Use IOCForge identity rules when grouping positive IOC overlap."""
    value = refang(value.strip())
    ioc_type = detect(value)
    if ioc_type == IocType.UNKNOWN:
        return value
    try:
        return normalize(value, ioc_type)
    except (UnicodeError, ValueError):
        return value


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


def load_fixture(path: str | Path) -> dict[str, Any]:
    """Read a bounded JSON fixture for CLI or API evaluation."""
    fixture_path = Path(path)
    if fixture_path.stat().st_size > MAX_EVALUATION_FIXTURE_BYTES:
        raise ValueError("evaluation fixture exceeds the 10 MiB size limit")
    try:
        with fixture_path.open(encoding="utf-8") as fixture_file:
            fixture = json.load(fixture_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("evaluation fixture must be valid UTF-8 JSON") from error
    if not isinstance(fixture, dict):
        raise ValueError("evaluation fixture root must be an object")
    return fixture


def _validate_fixture(fixture: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    if not isinstance(fixture, dict):
        raise ValueError("evaluation fixture root must be an object")
    if fixture.get("schema_version") != EVALUATION_SCHEMA_VERSION:
        raise ValueError("unsupported provider evaluation fixture schema")
    providers = fixture.get("providers")
    cases = fixture.get("cases")
    if (
        not isinstance(providers, list)
        or not providers
        or any(not isinstance(provider, str) or not provider for provider in providers)
        or len(set(providers)) != len(providers)
    ):
        raise ValueError("fixture providers must be a non-empty unique string list")
    if not isinstance(cases, list) or not cases:
        raise ValueError("fixture cases must be a non-empty list")
    provider_set = set(providers)
    seen_case_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or not isinstance(case.get("ioc"), str):
            raise ValueError(f"case {index} must include an IOC string")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen_case_ids:
            raise ValueError("fixture case IDs must be unique non-empty strings")
        seen_case_ids.add(case_id)
        truth = case.get("truth", {})
        truth_value = truth.get("malicious") if isinstance(truth, dict) else ...
        if not isinstance(truth, dict) or not (
            truth_value is None or isinstance(truth_value, bool)
        ):
            raise ValueError(f"case {case_id} truth.malicious must be boolean or null")
        expected = case.get("expected_sources", providers)
        if (
            not isinstance(expected, list)
            or any(not isinstance(source, str) or source not in provider_set for source in expected)
            or len(set(expected)) != len(expected)
        ):
            raise ValueError(f"case {case_id} expected_sources is invalid")
        if case.get("as_of") is not None:
            _timestamp(case["as_of"], "as_of")
        outcomes = case.get("sources", [])
        if not isinstance(outcomes, list):
            raise ValueError(f"case {case_id} sources must be a list")
        seen_sources: set[str] = set()
        for outcome in outcomes:
            if not isinstance(outcome, dict):
                raise ValueError(f"case {case_id} source outcomes must be objects")
            source = outcome.get("source")
            if not isinstance(source, str) or source not in expected or source in seen_sources:
                raise ValueError(
                    f"case {case_id} source outcomes must be unique and expected"
                )
            seen_sources.add(source)
            if not isinstance(outcome.get("found"), bool):
                raise ValueError(f"case {case_id} source {source} needs found boolean")
            malicious = outcome.get("malicious")
            if not (malicious is None or isinstance(malicious, bool)):
                raise ValueError(
                    f"case {case_id} source {source} malicious must be boolean or null"
                )
            if outcome.get("error") is not None and not isinstance(
                outcome.get("error"), str
            ):
                raise ValueError(f"case {case_id} source {source} error must be text")
            latency = outcome.get("latency_ms")
            if latency is not None and (
                not isinstance(latency, (int, float))
                or isinstance(latency, bool)
                or not math.isfinite(latency)
                or latency < 0
            ):
                raise ValueError(
                    f"case {case_id} source {source} latency_ms is invalid"
                )
            if not isinstance(outcome.get("cache_hit", False), bool):
                raise ValueError(f"case {case_id} source {source} cache_hit is invalid")
            if outcome.get("observed_at") is not None:
                _timestamp(outcome["observed_at"], "observed_at")
                if case.get("as_of") is not None:
                    _timestamp(case["as_of"], "as_of")
    return providers, cases


def evaluate_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Calculate reproducible provider metrics without live network access.

    Expected coverage is defined by ``expected_sources``. Missing source entries
    count as not attempted, while explicit ``error`` results count as failures.
    Latency excludes cache hits. Classification metrics use only boolean labels
    and successful boolean provider verdicts. Pair overlap uses positive IOC sets.
    """
    providers, cases = _validate_fixture(fixture)
    canonical_iocs = {
        case["id"]: _canonical_ioc(case["ioc"]) for case in cases
    }
    outcomes_by_case = {
        case["id"]: {outcome["source"]: outcome for outcome in case.get("sources", [])}
        for case in cases
    }
    metrics: dict[str, dict[str, Any]] = {}
    positive_iocs: dict[str, set[str]] = {provider: set() for provider in providers}
    predictions: dict[str, dict[str, bool]] = {provider: {} for provider in providers}

    for provider in providers:
        expected_count = 0
        attempted_count = 0
        successful_count = 0
        failures = 0
        latency_samples: list[float] = []
        freshness_samples: list[float] = []
        future_timestamps = 0
        true_positive = false_positive = true_negative = false_negative = 0
        labelled_count = 0

        for case in cases:
            expected = case.get("expected_sources", providers)
            if provider not in expected:
                continue
            expected_count += 1
            outcome = outcomes_by_case[case["id"]].get(provider)
            if outcome is None:
                continue
            attempted_count += 1
            if outcome.get("error") is not None:
                failures += 1
            if outcome["found"] and outcome.get("error") is None:
                successful_count += 1
            if outcome.get("latency_ms") is not None and not outcome.get(
                "cache_hit", False
            ):
                latency_samples.append(float(outcome["latency_ms"]))
            if (
                outcome["found"]
                and outcome.get("error") is None
                and isinstance(outcome.get("observed_at"), str)
                and isinstance(case.get("as_of"), str)
            ):
                age_seconds = (
                    _timestamp(case["as_of"], "as_of")
                    - _timestamp(outcome["observed_at"], "observed_at")
                ).total_seconds()
                freshness_samples.append(age_seconds)
                if age_seconds < 0:
                    future_timestamps += 1
            truth = case.get("truth", {}).get("malicious")
            predicted = outcome.get("malicious")
            if (
                outcome["found"]
                and outcome.get("error") is None
                and isinstance(truth, bool)
                and isinstance(predicted, bool)
            ):
                labelled_count += 1
                if truth and predicted:
                    true_positive += 1
                elif truth and not predicted:
                    false_negative += 1
                elif not truth and predicted:
                    false_positive += 1
                else:
                    true_negative += 1
            if (
                outcome["found"]
                and outcome.get("error") is None
                and outcome.get("malicious") is True
            ):
                positive_iocs[provider].add(canonical_iocs[case["id"]])
            if (
                outcome["found"]
                and outcome.get("error") is None
                and isinstance(outcome.get("malicious"), bool)
            ):
                predictions[provider][case["id"]] = outcome["malicious"]

        precision = _ratio(true_positive, true_positive + false_positive)
        recall = _ratio(true_positive, true_positive + false_negative)
        negative_recall = _ratio(true_negative, true_negative + false_positive)
        specificity = negative_recall
        classification_intervals = {
            "precision": _wilson_interval(
                true_positive, true_positive + false_positive
            ),
            "recall": _wilson_interval(
                true_positive, true_positive + false_negative
            ),
            "specificity": _wilson_interval(
                true_negative, true_negative + false_positive
            ),
        }
        balanced_accuracy = (
            round((recall + negative_recall) / 2, 4)
            if recall is not None and negative_recall is not None
            else None
        )
        reliability_weight_candidate = (
            round(max(0.0, 2 * balanced_accuracy - 1), 4)
            if balanced_accuracy is not None
            else None
        )
        f1 = (
            round(2 * precision * recall / (precision + recall), 4)
            if precision is not None
            and recall is not None
            and precision + recall > 0
            else (0.0 if precision == 0 and recall == 0 else None)
        )
        metrics[provider] = {
            "expected_count": expected_count,
            "attempted_count": attempted_count,
            "not_attempted_count": expected_count - attempted_count,
            "found_count": successful_count,
            "coverage": _ratio(successful_count, expected_count),
            "coverage_interval_95": _wilson_interval(
                successful_count, expected_count
            ),
            "failure_count": failures,
            "failure_rate": _ratio(failures, attempted_count),
            "failure_rate_interval_95": _wilson_interval(failures, attempted_count),
            "latency_ms": {
                "sample_count": len(latency_samples),
                "mean": _mean(latency_samples),
                "p50": _percentile(latency_samples, 0.5),
                "p95": _percentile(latency_samples, 0.95),
            },
            "freshness_age_seconds": {
                "sample_count": len(freshness_samples),
                "mean": _mean(freshness_samples),
                "p50": _percentile(freshness_samples, 0.5),
                "future_timestamp_count": future_timestamps,
            },
            "classification": {
                "labelled_count": labelled_count,
                "true_positive": true_positive,
                "false_positive": false_positive,
                "true_negative": true_negative,
                "false_negative": false_negative,
                "precision": precision,
                "recall": recall,
                "specificity": specificity,
                "f1": f1,
                "balanced_accuracy": balanced_accuracy,
                "reliability_weight_candidate": {
                    "method": "clamped_youden_j_v1",
                    "value": reliability_weight_candidate,
                    "labelled_count": labelled_count,
                    "positive_count": true_positive + false_negative,
                    "negative_count": true_negative + false_positive,
                },
                "wilson_intervals_95": classification_intervals,
            },
        }

    provider_disagreement: dict[str, dict[str, Any]] = {}
    compared_pairs = disagreements = 0
    for provider in providers:
        local_pairs = local_disagreements = 0
        for other in providers:
            if other == provider:
                continue
            shared_cases = predictions[provider].keys() & predictions[other].keys()
            for case_id in shared_cases:
                local_pairs += 1
                compared_pairs += 1
                if predictions[provider][case_id] != predictions[other][case_id]:
                    local_disagreements += 1
                    disagreements += 1
        provider_disagreement[provider] = {
            "compared_predictions": local_pairs,
            "disagreements": local_disagreements,
            "rate": _ratio(local_disagreements, local_pairs),
        }
    overlap = []
    for left, right in combinations(providers, 2):
        intersection = positive_iocs[left] & positive_iocs[right]
        union = positive_iocs[left] | positive_iocs[right]
        overlap.append(
            {
                "left": left,
                "right": right,
                "left_positive_count": len(positive_iocs[left]),
                "right_positive_count": len(positive_iocs[right]),
                "intersection_count": len(intersection),
                "union_count": len(union),
                "jaccard": _ratio(len(intersection), len(union)),
            }
        )

    return {
        "methodology": EVALUATION_METHODOLOGY,
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "ioc_normalization_version": IOC_NORMALIZATION_VERSION,
        "dataset_name": fixture.get("name", "unnamed"),
        "dataset_sha256": hashlib.sha256(_canonical_json(fixture)).hexdigest(),
        "case_count": len(cases),
        "providers": metrics,
        "disagreement": {
            "compared_predictions": compared_pairs,
            "disagreements": disagreements,
            "rate": _ratio(disagreements, compared_pairs),
            "by_provider": provider_disagreement,
        },
        "positive_overlap": overlap,
        "reliability_note": (
            "Metrics and Wilson score intervals describe only this fixture. "
            "Balanced accuracy is reported when both truth classes are measurable. "
            "Small or unrepresentative samples must not be treated as production "
            "reliability weights."
        ),
    }
