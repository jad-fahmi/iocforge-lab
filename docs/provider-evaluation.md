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
- **Latency** includes attempted results with `latency_ms`; cache hits are
  excluded. Mean and nearest-rank p50/p95 are reported in milliseconds.
- **Freshness** is `as_of - observed_at` for successful results with both
  timestamps. Negative ages are retained and counted as future timestamps.
- **False positives, false negatives, precision, recall, F1, and balanced
  accuracy** use only cases with boolean ground truth and successful boolean
  provider verdicts. Balanced accuracy is omitted unless both truth classes
  have measurable recall.
- **Disagreement** compares successful boolean verdicts pairwise for the same
  case. **Overlap** is Jaccard similarity between providers' sets of positively
  classified IOC values.

The report includes a SHA-256 digest of canonicalized fixture JSON and a fixed
methodology version. Re-running the same fixture produces the same report. The
example fixture is intentionally small and demonstrates a provider outage,
rate-limit error, conflicting verdict, stale evidence, a future timestamp, and
an incomplete result. Its numbers are not production reliability estimates.
IOCForge reports evidence for review but does not automatically turn a small
fixture score into a provider weight.

Every `SourceResult` now carries the engine-measured lookup duration. Results
served from the cache set `cache_hit`, allowing the evaluator to keep local cache
latency out of provider latency summaries. Both fields remain attached to the
enrichment snapshot; deduplicated evidence identity remains based on the
provider payload and its collection provenance.
