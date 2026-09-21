# Scoring methodology

The current methodology version is `1`. Each found source contributes a signal
weighted by provider reliability. Malicious signals use the provider's
normalized score; clean findings contribute weight without malicious signal.
The aggregate is a deterministic weighted average, then mapped to verdicts:

| Score | Verdict |
| --- | --- |
| 0 | clean |
| >0 and <0.25 | low |
| >=0.25 and <0.6 | suspicious |
| >=0.6 | malicious |

Observations older than 30 days are progressively discounted. Local allowlists,
private ranges, and known scanner tags reduce false positives, while a local
blocklist establishes a minimum malicious score. Responses include evidence,
counter-evidence, no-data sources, errors, reason codes, and a recommended
action so analysts can inspect why a verdict was reached.

Scores are decision support, not an automated containment authority. Conflicting
sources should be reviewed alongside local telemetry.
