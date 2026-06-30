"""Explainable aggregation of source results into an analyst verdict."""

import math
from datetime import datetime, timezone

METHODOLOGY_VERSION = "2"
_METHODOLOGY_V2_VERSION = "2"

DEFAULT_WEIGHTS = {
    "virustotal": 1.0,
    "abuseipdb": 0.8,
    "otx": 0.7,
    "greynoise": 0.6,
    "urlhaus": 0.9,
    "threatfox": 0.85,
    "malwarebazaar": 0.9,
    "hashlookup": 0.0,
    "urlscan": 0.0,
    "shodan": 0.0,
}

DEFAULT_THRESHOLDS = {"suspicious": 0.25, "malicious": 0.6}


def _score_v2(result, settings=None, as_of=None):
    scored_at = _as_utc(as_of) if as_of is not None else datetime.now(timezone.utc)
    snapshot = settings_snapshot(settings)
    explanation = explain(result, settings=snapshot, as_of=scored_at)
    result.score = explanation["score"]
    result.verdict = explanation["verdict"]
    result.confidence = explanation["confidence"]
    result.evidence = explanation["evidence"]
    result.counter_evidence = explanation["counter_evidence"]
    result.no_data = explanation["no_data"]
    result.errors = explanation["errors"]
    result.reason_codes = explanation["reason_codes"]
    result.decision_trace = explanation["decision_trace"]
    result.recommended_action = explanation["recommended_action"]
    result.scoring_version = _METHODOLOGY_V2_VERSION
    result.scoring_config = snapshot
    result.scored_at = scored_at.isoformat()
    return result.score, result.verdict


_SCORING_METHODOLOGIES = {_METHODOLOGY_V2_VERSION: _score_v2}


def supports_scoring_version(version: str | None) -> bool:
    """Return whether this installation retains an implementation of a method."""
    return version in _SCORING_METHODOLOGIES


def score_for_version(result, version: str, settings=None, as_of=None):
    """Replay with the pinned scoring implementation, independent of the active one."""
    scorer = _SCORING_METHODOLOGIES.get(version)
    if scorer is None:
        raise ValueError(f"unsupported scoring methodology version: {version}")
    return scorer(result, settings=settings, as_of=as_of)


def score(result, settings=None, as_of=None):
    """Score a live result with the active methodology version."""
    return score_for_version(
        result, METHODOLOGY_VERSION, settings=settings, as_of=as_of
    )


def explain(result, settings=None, as_of=None):
    evaluation_time = (
        _as_utc(as_of) if as_of is not None else datetime.now(timezone.utc)
    )
    weights, thresholds = _settings(settings)
    evidence = []
    counter_evidence = []
    no_data = []
    errors = []
    reason_codes = []
    weighted_signal = 0.0
    total_weight = 0.0
    observation_trace = []

    for source in result.sources:
        weight = weights.get(source.source, 0.5)
        age_factor = _freshness_factor(source, evaluation_time)
        observed_at = _observed_at(source)
        adjusted_weight = weight * age_factor
        status = "unclassified"
        included = False
        numerator = 0.0
        if source.error:
            errors.append({"source": source.source, "error": source.error})
            status = "error"
        elif not source.found:
            no_data.append(source.source)
            status = "no_data"
        else:
            codes = reason_codes_for(source, as_of=evaluation_time)
            reason_codes.extend(codes)

            item = {
                "source": source.source,
                "score": source.score,
                "reason_codes": codes,
                "age_factor": age_factor,
                "summary": _summary(source),
            }

            if source.malicious:
                evidence.append(item)
                status = "malicious"
                if adjusted_weight:
                    numerator = adjusted_weight * (
                        source.score if source.score is not None else 1.0
                    )
                    weighted_signal += numerator
                    total_weight += adjusted_weight
                    included = True
            elif source.malicious is False:
                counter_evidence.append(item)
                status = "benign"
                if adjusted_weight:
                    total_weight += adjusted_weight
                    included = True

        trace_item = {
            "source": source.source,
            "collected_at": source.collected_at,
            "observed_at": observed_at.isoformat() if observed_at else None,
            "raw_response_sha256": source.raw_response_sha256,
            "status": status,
            "score": source.score,
            "confidence": source.confidence,
            "configured_weight": weight,
            "freshness_factor": age_factor,
            "applied_weight": adjusted_weight,
            "included_in_aggregate": included,
            "weighted_signal_contribution": round(numerator, 6),
            "ignored_reason": (
                "provider_error"
                if status == "error"
                else "provider_returned_no_data"
                if status == "no_data"
                else "provider_has_no_verdict"
                if status == "unclassified"
                else "zero_effective_weight"
                if not included
                else None
            ),
        }
        warnings = _metadata_warnings(source, observed_at)
        if warnings:
            trace_item["metadata_warnings"] = warnings
        observation_trace.append(trace_item)

    internal = getattr(result, "internal_context", {}) or {}
    internal_reasons = internal.get("reasons", [])
    reason_codes.extend(internal_reasons)

    base_score = round(weighted_signal / total_weight, 3) if total_weight else 0.0
    final = base_score
    context_adjustments = []
    if "local_blocklist" in internal_reasons:
        final = max(final, 0.85)
        context_adjustments.append(
            {"reason": "local_blocklist", "operation": "floor", "value": 0.85}
        )
    if "allowlisted_asset" in internal_reasons or "private_ip" in internal_reasons:
        final = round(final * 0.25, 3)
        context_adjustments.append(
            {
                "reason": "allowlisted_asset_or_private_ip",
                "operation": "multiply",
                "value": 0.25,
            }
        )
    if "known_scanner" in internal_reasons:
        final = min(final, 0.2)
        context_adjustments.append(
            {"reason": "known_scanner", "operation": "cap", "value": 0.2}
        )

    verdict = verdict_for(final, thresholds=thresholds)
    confidence = confidence_for(evidence, counter_evidence, errors, no_data)
    decision_trace = {
        "methodology_version": _METHODOLOGY_V2_VERSION,
        "evaluated_at": evaluation_time.isoformat(),
        "observations": observation_trace,
        "weighted_signal": round(weighted_signal, 6),
        "total_weight": round(total_weight, 6),
        "base_score": base_score,
        "context_adjustments": context_adjustments,
        "final_score": final,
        "thresholds": thresholds,
    }
    unavailable_providers = getattr(result, "unavailable_providers", []) or []
    if unavailable_providers:
        decision_trace["unavailable_providers"] = unavailable_providers
    return {
        "score": final,
        "verdict": verdict,
        "confidence": confidence,
        "evidence": evidence,
        "counter_evidence": counter_evidence,
        "no_data": sorted(no_data),
        "errors": errors,
        "reason_codes": sorted(set(reason_codes)),
        "recommended_action": recommended_action(verdict, confidence, internal),
        "decision_trace": decision_trace,
    }


def settings_snapshot(settings=None):
    """Return the full effective scoring configuration used for a decision."""
    weights, thresholds = _settings(settings)
    return {"weights": weights, "thresholds": thresholds}


def verdict_for(value, thresholds=None):
    _, thresholds = _settings({"thresholds": thresholds} if thresholds else None)
    if value >= thresholds["malicious"]:
        return "malicious"
    if value >= thresholds["suspicious"]:
        return "suspicious"
    if value > 0:
        return "low"
    return "clean"


def _settings(settings):
    settings = settings or {}
    weights = {**DEFAULT_WEIGHTS, **settings.get("weights", {})}
    thresholds = {**DEFAULT_THRESHOLDS, **settings.get("thresholds", {})}
    suspicious = float(thresholds["suspicious"])
    malicious = float(thresholds["malicious"])
    if not 0 <= suspicious <= malicious <= 1:
        raise ValueError(
            "scoring thresholds must satisfy 0 <= suspicious <= malicious <= 1"
        )
    return (
        {name: float(weight) for name, weight in weights.items()},
        {
            "suspicious": suspicious,
            "malicious": malicious,
        },
    )


def confidence_for(evidence, counter_evidence, errors, no_data):
    if len(evidence) >= 2 and not errors:
        return "high"
    if evidence and counter_evidence:
        return "medium"
    if evidence:
        return "medium" if len(errors) < 2 else "low"
    if counter_evidence and len(no_data) <= 2:
        return "medium"
    return "low"


def recommended_action(verdict, confidence, internal):
    tags = set((internal or {}).get("tags", []))
    if verdict == "malicious":
        return "Contain related hosts, block the IOC, and open an incident ticket."
    if verdict == "suspicious":
        return "Hunt for related activity and block if it is not business-approved."
    if "internal_asset" in tags or "corp_domain" in tags:
        return "Treat as business context; verify ownership before escalating."
    if verdict == "low":
        return "Monitor and correlate with recent endpoint, proxy, and authentication telemetry."
    return "No immediate action; document blind spots and recheck if new telemetry appears."


def reason_codes_for(source, as_of=None):
    raw = _raw_dict(source)
    codes = []
    if source.source == "virustotal":
        stats = raw.get("stats", {})
        if isinstance(stats, dict) and any(
            _finite_number(stats.get(key))
            and stats[key] > 0
            for key in ("malicious", "suspicious")
        ):
            codes.append("vt_malicious_votes")
    if source.source == "abuseipdb":
        abuse_score = raw.get("abuseConfidenceScore")
        if (
            _finite_number(abuse_score)
            and abuse_score >= 75
        ):
            codes.append("abuseipdb_high_confidence")
    if source.source == "greynoise":
        if raw.get("classification") == "benign":
            codes.append("greynoise_benign")
        if raw.get("noise"):
            codes.append("known_scanner")
    if _observed_at(source):
        codes.append(
            "recent_observation"
            if _freshness_factor(source, as_of) >= 0.75
            else "stale_observation"
        )
    return codes


def _summary(source):
    raw = _raw_dict(source)
    if source.source == "virustotal":
        return f"analysis stats {raw.get('stats', {})}"
    if source.source == "abuseipdb":
        return f"confidence {raw.get('abuseConfidenceScore', 0)}"
    if source.source == "greynoise":
        return f"classification {raw.get('classification', 'unknown')}"
    if source.source == "otx":
        return f"pulse count {raw.get('pulse_count', 0)}"
    if source.source == "shodan":
        return f"open ports {raw.get('ports', [])}"
    if source.source == "urlhaus":
        return f"malware URL status {raw.get('url_status', 'unknown')}"
    if source.source == "threatfox":
        return f"matched {raw.get('ioc_count', 0)} curated malware IOC(s)"
    if source.source == "malwarebazaar":
        return f"confirmed malware sample {raw.get('file_name', 'unknown')}"
    if source.source == "hashlookup":
        return f"known file metadata {raw.get('file_name', 'unknown')}"
    if source.source == "urlscan":
        return f"observed in {raw.get('scan_count', 0)} historical scan(s)"
    return "source reported data"


def _freshness_factor(source, as_of=None):
    observed = _observed_at(source)
    if observed is None:
        return 1.0
    evaluation_time = (
        _as_utc(as_of) if as_of is not None else datetime.now(timezone.utc)
    )
    age_days = max(0, (evaluation_time - observed).days)
    if age_days <= 30:
        return 1.0
    if age_days <= 90:
        return 0.75
    if age_days <= 180:
        return 0.5
    return 0.25


def _observed_at(source):
    value = source.observed_at
    raw = _raw_dict(source)
    for key in ("observed_at", "last_seen", "last_observed", "last_analysis_date"):
        value = value or raw.get(key)
    if not value:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not _finite_number(value):
            return None
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _raw_dict(source):
    raw = getattr(source, "raw", None)
    return raw if isinstance(raw, dict) else {}


def _observed_at_present(source):
    value = getattr(source, "observed_at", None)
    if value is not None and value != "":
        return True
    raw = _raw_dict(source)
    return any(
        raw.get(key) is not None and raw.get(key) != ""
        for key in ("observed_at", "last_seen", "last_observed", "last_analysis_date")
    )


def _metadata_warnings(source, observed_at):
    warnings = []
    if not isinstance(source.raw, dict):
        warnings.append("raw_payload_not_object")
    raw = _raw_dict(source)
    if _observed_at_present(source) and observed_at is None:
        warnings.append("invalid_observation_timestamp")
    if source.source == "virustotal" and "stats" in raw:
        stats = raw["stats"]
        if not isinstance(stats, dict) or any(
            key in stats and not _finite_number(stats[key])
            for key in ("malicious", "suspicious")
        ):
            warnings.append("invalid_virustotal_stats")
    if source.source == "abuseipdb" and "abuseConfidenceScore" in raw:
        abuse_score = raw["abuseConfidenceScore"]
        if not _finite_number(abuse_score) or not 0 <= abuse_score <= 100:
            warnings.append("invalid_abuseipdb_confidence_score")
    return warnings


def _finite_number(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _as_utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
