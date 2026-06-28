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
action so analysts can inspect why a verdict was reached. The trace also lists
providers that could not contribute because they were disabled, lacked required
credentials, were omitted by the source filter, or were skipped as optional.
These availability records do not affect the score and are preserved during
history and offline bundle replay.

Malformed optional provider metadata cannot crash aggregation. Invalid raw
shapes, unparseable observation times, and malformed provider reason fields are
omitted from freshness or reason-code extraction and listed as
`metadata_warnings` on the affected observation trace. An unusable timestamp
uses the existing no-usable-time freshness factor; the normalized top-level
provider verdict and score remain visible in the trace.

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

The default provider weights are starting priors, not empirical accuracy
estimates. The offline provider evaluator reports a clamped Youden's J weight
candidate from successful labeled verdicts, along with the labeled sample
counts. Review that candidate with coverage, failure rate, and the reported
confidence intervals using representative local labels before changing
`scoring.weights`; evaluation never changes scoring configuration automatically.
