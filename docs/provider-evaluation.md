# Provider evaluation fixtures

IOCForge evaluates saved provider outcomes offline. It never queries a live
provider during evaluation. Run the checked-in example with:

```shell
ioc-enrich --evaluate-fixture tests/fixtures/provider-evaluation-v1.json
```

The API accepts the same JSON object at `POST /api/v1/evaluation/run`. The
fixture root contains `schema_version: 1`, a `name`, a unique `providers` list,
and non-empty `cases`. Each case has a unique `id`, an `ioc`, optional `as_of`,
`truth.malicious` (`true`, `false`, or `null`), optional `expected_sources`, and
a `sources` list. Each source result records `source`, `found`, `malicious`,
optional `error`, `observed_at`, `latency_ms`, and `cache_hit`.

## Metric definitions

- **Coverage** is successful `found` outcomes divided by expected provider
  attempts. A provider listed as expected but missing from the case is counted
  as not attempted. An explicit error is attempted but not covered.
- **Failure rate** is source results with a non-null error divided by attempted
  results.
- **Coverage and failure-rate intervals** are two-sided 95% Wilson score
  intervals over expected and attempted outcomes respectively. A zero denominator
  produces no interval.
- **Latency** includes attempted results with `latency_ms`; cache hits are
  excluded. Mean and nearest-rank p50/p95 are reported in milliseconds.
- **Freshness** is `as_of - observed_at` for successful results with both
  timestamps. Negative ages are retained and counted as future timestamps.
- **False positives, false negatives, precision, recall, F1, and balanced
  accuracy** use only cases with boolean ground truth and successful boolean
  provider verdicts. Balanced accuracy is omitted unless both truth classes
  have measurable recall. The report includes 95% Wilson intervals for precision,
  recall, and specificity when their denominators are non-zero.
- **Detection misses** are successful, expected provider attempts for labeled
  malicious cases where the provider returned `found: false`. Their rate is
  missed malicious cases divided by expected malicious cases with a non-error
  provider response. The report includes the number expected, attempted, and
  missed, plus a 95% Wilson interval. Provider errors and missing attempts are
  excluded from this denominator and remain visible in failure and coverage
  metrics. A detection miss is separate from a false negative verdict: a
  successful `found: true, malicious: false` outcome is a classification false
  negative but still counts as detection.
- **Reliability weight candidate** is the clamped Youden's J statistic,
  `max(0, 2 * balanced_accuracy - 1)`. It ranges from zero for chance-level or
  inverted predictions to one for perfect predictions. The report includes
  positive, negative, and total labeled sample counts. It is conditional on
  successful classified outcomes; use coverage and failure rate alongside it.
- **Disagreement** compares successful boolean verdicts pairwise for the same
  case. **Overlap** is Jaccard similarity between providers' sets of positively
classified IOC values. IOC values are canonicalized with the same refanging,
type detection, and normalization rules used by enrichment before set overlap
is calculated. The report records the IOC normalization version alongside the
fixture digest.

The report includes a SHA-256 digest of canonicalized fixture JSON and a fixed
methodology version (`iocforge-provider-evaluation-v5`). Re-running the same
fixture produces the same report. Wilson intervals assume independent binomial
outcomes; repeated or correlated indicators and unrepresentative labels can make
them overconfident. They expose sample size uncertainty, not provider accuracy
outside the fixture. The
example fixture is intentionally small and demonstrates a provider outage,
rate-limit error, conflicting verdict, stale evidence, a future timestamp, and
an incomplete result. Its numbers are not production reliability estimates.
IOCForge reports the candidate for review but does not apply it to scoring
weights. Existing default weights are operator priors, not measurements from
this example fixture. Operators should use representative, locally labeled
data and review the labeled sample counts and uncertainty before changing a
weight.

Every `SourceResult` now carries the engine-measured lookup duration. Results
served from the cache set `cache_hit`, allowing the evaluator to keep local cache
latency out of provider latency summaries. Both fields remain attached to the
enrichment snapshot; deduplicated evidence identity remains based on the
provider payload and its collection provenance.
