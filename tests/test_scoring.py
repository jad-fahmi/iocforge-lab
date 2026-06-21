from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import score, verdict_for


def _res(sources):
    r = EnrichmentResult(ioc="x", ioc_type=IocType.IPV4)
    for s in sources:
        r.add(s)
    return r


def test_clean_when_nothing_flags():
    r = _res(
        [
            SourceResult(
                "virustotal", "x", IocType.IPV4, found=True, malicious=False, score=0.0
            )
        ]
    )
    val, verdict = score(r)
    assert verdict == "clean"
    assert val == 0.0


def test_malicious_from_strong_source():
    r = _res(
        [
            SourceResult(
                "virustotal", "x", IocType.IPV4, found=True, malicious=True, score=1.0
            )
        ]
    )
    val, verdict = score(r)
    assert verdict == "malicious"


def test_shodan_does_not_move_score():
    r = _res([SourceResult("shodan", "x", IocType.IPV4, found=True, malicious=None)])
    val, _ = score(r)
    assert val == 0.0


def test_verdict_buckets():
    assert verdict_for(0.7) == "malicious"
    assert verdict_for(0.3) == "suspicious"
    assert verdict_for(0.05) == "low"
    assert verdict_for(0.0) == "clean"


def test_score_attaches_explainable_evidence():
    r = _res(
        [
            SourceResult(
                "virustotal",
                "x",
                IocType.IPV4,
                found=True,
                malicious=True,
                score=0.7,
                raw={"stats": {"malicious": 4, "suspicious": 0}},
            ),
            SourceResult(
                "greynoise",
                "x",
                IocType.IPV4,
                found=True,
                malicious=False,
                score=0.0,
                raw={"classification": "benign"},
            ),
            SourceResult("otx", "x", IocType.IPV4, found=False),
            SourceResult("abuseipdb", "x", IocType.IPV4, error="timeout"),
        ]
    )

    score(r)

    assert r.verdict == "suspicious"
    assert r.evidence[0]["source"] == "virustotal"
    assert r.counter_evidence[0]["source"] == "greynoise"
    assert r.no_data == ["otx"]
    assert r.errors == [{"source": "abuseipdb", "error": "timeout"}]
    assert "vt_malicious_votes" in r.reason_codes
    assert "greynoise_benign" in r.reason_codes


def test_stale_observation_has_less_weight():
    fresh = _res(
        [
            SourceResult(
                "virustotal",
                "x",
                IocType.IPV4,
                found=True,
                malicious=True,
                score=1.0,
                raw={"last_seen": "2026-08-01T00:00:00+00:00"},
            ),
            SourceResult(
                "abuseipdb", "x", IocType.IPV4, found=True, malicious=False, score=0.0
            ),
        ]
    )
    stale = _res(
        [
            SourceResult(
                "virustotal",
                "x",
                IocType.IPV4,
                found=True,
                malicious=True,
                score=1.0,
                raw={"last_seen": "2024-01-01T00:00:00+00:00"},
            ),
            SourceResult(
                "abuseipdb", "x", IocType.IPV4, found=True, malicious=False, score=0.0
            ),
        ]
    )

    score(fresh)
    score(stale)

    assert stale.score < fresh.score
    assert "stale_observation" in stale.reason_codes


def test_allowlisted_internal_context_reduces_score():
    r = _res(
        [
            SourceResult(
                "virustotal",
                "10.0.0.4",
                IocType.IPV4,
                found=True,
                malicious=True,
                score=1.0,
            )
        ]
    )
    r.internal_context = {
        "tags": ["internal_asset"],
        "reasons": ["allowlisted_asset", "private_ip"],
    }

    score(r)

    assert r.verdict == "suspicious"
    assert r.score == 0.25
    assert "allowlisted_asset" in r.reason_codes


def test_configured_thresholds_change_verdict_and_record_version():
    r = _res(
        [
            SourceResult(
                "custom", "x", IocType.IPV4, found=True, malicious=True, score=0.4
            )
        ]
    )

    score(
        r,
        settings={
            "weights": {"custom": 1.0},
            "thresholds": {
                "suspicious": 0.2,
                "malicious": 0.4,
            },
        },
    )

    assert r.verdict == "malicious"
    assert r.scoring_version == "2"


def test_decision_trace_records_weights_and_why_observations_were_ignored():
    result = _res(
        [
            SourceResult(
                "virustotal",
                "x",
                IocType.IPV4,
                found=True,
                malicious=True,
                score=0.8,
            ),
            SourceResult("shodan", "x", IocType.IPV4, found=True),
            SourceResult("otx", "x", IocType.IPV4, error="timeout"),
        ]
    )

    score(result, as_of="2026-09-20T00:00:00+00:00")

    assert result.scoring_config["weights"]["virustotal"] == 1.0
    assert result.scored_at == "2026-09-20T00:00:00+00:00"
    trace = result.decision_trace["observations"]
    assert trace[0]["included_in_aggregate"] is True
    assert trace[1]["ignored_reason"] == "provider_has_no_verdict"
    assert trace[2]["ignored_reason"] == "provider_error"


def test_invalid_thresholds_are_rejected():
    r = _res([])

    try:
        score(r, settings={"thresholds": {"suspicious": 0.8, "malicious": 0.6}})
    except ValueError as error:
        assert "thresholds" in str(error)
    else:
        raise AssertionError("invalid thresholds must fail")
