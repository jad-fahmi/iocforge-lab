"""Explainable aggregation of source results into an analyst verdict."""

from datetime import datetime, timezone

METHODOLOGY_VERSION = "1"

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


def score(result, settings=None):
    explanation = explain(result, settings=settings)
    result.score = explanation["score"]
    result.verdict = explanation["verdict"]
    result.confidence = explanation["confidence"]
    result.evidence = explanation["evidence"]
    result.counter_evidence = explanation["counter_evidence"]
    result.no_data = explanation["no_data"]
    result.errors = explanation["errors"]
    result.reason_codes = explanation["reason_codes"]
    result.recommended_action = explanation["recommended_action"]
    result.scoring_version = METHODOLOGY_VERSION
    return result.score, result.verdict


def explain(result, settings=None):
    weights, thresholds = _settings(settings)
    evidence = []
    counter_evidence = []
    no_data = []
    errors = []
    reason_codes = []
    weighted_signal = 0.0
    total_weight = 0.0

    for source in result.sources:
        if source.error:
            errors.append({"source": source.source, "error": source.error})
            continue
        if not source.found:
            no_data.append(source.source)
            continue

        weight = weights.get(source.source, 0.5)
        age_factor = _freshness_factor(source)
        adjusted_weight = weight * age_factor
        codes = reason_codes_for(source)
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
            if adjusted_weight:
                weighted_signal += adjusted_weight * (
                    source.score if source.score is not None else 1.0
                )
                total_weight += adjusted_weight
        elif source.malicious is False:
            counter_evidence.append(item)
            if adjusted_weight:
                total_weight += adjusted_weight

    internal = getattr(result, "internal_context", {}) or {}
    internal_reasons = internal.get("reasons", [])
    reason_codes.extend(internal_reasons)

    final = round(weighted_signal / total_weight, 3) if total_weight else 0.0
    if "local_blocklist" in internal_reasons:
        final = max(final, 0.85)
    if "allowlisted_asset" in internal_reasons or "private_ip" in internal_reasons:
        final = round(final * 0.25, 3)
    if "known_scanner" in internal_reasons:
        final = min(final, 0.2)

    verdict = verdict_for(final, thresholds=thresholds)
    confidence = confidence_for(evidence, counter_evidence, errors, no_data)
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
    }


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


def reason_codes_for(source):
    raw = source.raw or {}
    codes = []
    if source.source == "virustotal":
        stats = raw.get("stats", {})
        if stats.get("malicious", 0) or stats.get("suspicious", 0):
            codes.append("vt_malicious_votes")
    if source.source == "abuseipdb" and raw.get("abuseConfidenceScore", 0) >= 75:
        codes.append("abuseipdb_high_confidence")
    if source.source == "greynoise":
        if raw.get("classification") == "benign":
            codes.append("greynoise_benign")
        if raw.get("noise"):
            codes.append("known_scanner")
    if _observed_at(source):
        codes.append(
            "recent_observation"
            if _freshness_factor(source) >= 0.75
            else "stale_observation"
        )
    return codes


def _summary(source):
    if source.source == "virustotal":
        return f"analysis stats {source.raw.get('stats', {})}"
    if source.source == "abuseipdb":
        return f"confidence {source.raw.get('abuseConfidenceScore', 0)}"
    if source.source == "greynoise":
        return f"classification {source.raw.get('classification', 'unknown')}"
    if source.source == "otx":
        return f"pulse count {source.raw.get('pulse_count', 0)}"
    if source.source == "shodan":
        return f"open ports {source.raw.get('ports', [])}"
    if source.source == "urlhaus":
        return f"malware URL status {source.raw.get('url_status', 'unknown')}"
    if source.source == "threatfox":
        return f"matched {source.raw.get('ioc_count', 0)} curated malware IOC(s)"
    if source.source == "malwarebazaar":
        return f"confirmed malware sample {source.raw.get('file_name', 'unknown')}"
    if source.source == "hashlookup":
        return f"known file metadata {source.raw.get('file_name', 'unknown')}"
    if source.source == "urlscan":
        return f"observed in {source.raw.get('scan_count', 0)} historical scan(s)"
    return "source reported data"


def _freshness_factor(source):
    observed = _observed_at(source)
    if observed is None:
        return 1.0
    age_days = max(0, (datetime.now(timezone.utc) - observed).days)
    if age_days <= 30:
        return 1.0
    if age_days <= 90:
        return 0.75
    if age_days <= 180:
        return 0.5
    return 0.25


def _observed_at(source):
    value = source.observed_at
    raw = source.raw or {}
    for key in ("observed_at", "last_seen", "last_observed", "last_analysis_date"):
        value = value or raw.get(key)
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
