# Scoring methodology

The current methodology version is `2`. Each found source contributes a signal
weighted by provider reliability. Malicious signals use the provider's
normalized score; clean findings contribute weight without malicious signal.
The aggregate is a deterministic weighted average, then mapped to verdicts:

| Score | Verdict |
| --- | --- |
| 0 | clean |
| >0 and <0.25 | low |
| >=0.25 and <0.6 | suspicious |
| >=0.6 | malicious |

Observations older than 30 days are progressively discounted against the pinned
scoring time. Each enrichment snapshot stores the effective weights and
thresholds, scoring time, methodology version, and a trace of each provider
observation's status, configured weight, freshness factor, applied weight,
weighted contribution, and reason for exclusion. The trace also records the
aggregate before and after local-context adjustments. Local allowlists,
private ranges, and known scanner tags reduce false positives, while a local
blocklist establishes a minimum malicious score. Responses include evidence,
counter-evidence, no-data sources, errors, reason codes, and a recommended
action so analysts can inspect why a verdict was reached.

Scores are decision support, not an automated containment authority. Conflicting
sources should be reviewed alongside local telemetry.

## Configuration

Set `scoring.weights` and `scoring.thresholds` in local `config.json` to tune
the source reliability weights and suspicious/malicious boundaries. Thresholds
must satisfy `0 <= suspicious <= malicious <= 1`. Every result carries the
`scoring_version` so historical decisions can be interpreted correctly. Use
`ioc-enrich --replay <history-id>` or `GET /api/v1/history/{id}/replay` to
recalculate a saved decision from its stored observations and configuration.
Replay marks a record unavailable when it lacks pinned scoring inputs or uses
an unsupported methodology version; it does not substitute current settings.
