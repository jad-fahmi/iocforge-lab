# Local performance measurements

Run the offline workload from the repository root:

```shell
python -m benchmarks.run_benchmarks
```

The default generates 100 normalized domains and runs two deterministic local
provider adapters per domain. It measures enrichment throughput with the
scheduler alone and with SQLite persistence, observed peak concurrent work,
investigation linking, historical replay, direct pivot lookup, a fixed
three-edge multi-hop pivot path, row growth, and database growth above the
initialized schema size. It prints a JSON report and never calls external
providers or writes to the user's history database.

Snapshot replay samples re-score individual enrichments. A separate
investigation replay measurement reconstructs the generated case at a recorded
`as_of` point and records indicator count, graph size, truncation, and replay
completeness. The benchmark rejects incomplete investigation state or
unreplayable snapshots; bounded graph truncation is reported separately.

Adjust workload size, simulated provider delay, and worker limits when comparing
scheduler behavior:

```shell
python -m benchmarks.run_benchmarks \
  --indicators 1000 \
  --provider-delay-ms 5 \
  --lookup-workers 8 \
  --scheduler-concurrency 8 \
  --max-pending 32 \
  --replay-samples 100 \
  --repeats 5 \
  --warmup-runs 1 \
  --json-output benchmark-report.json
```

By default, the CLI performs one warm-up run and summarizes three measured
runs. Its JSON contains every run plus per-metric mean, median, standard
deviation, minimum, maximum, and nearest-rank p50/p95. Set
`--repeats 1 --warmup-runs 0` to capture a single sample. The report includes a
digest of the generated IOC set and pivot-path fixture, methodology version,
runtime, platform, parameters, row counts, and timings. Timings are specific to the
machine and its current load; compare runs only with the same parameters and
environment. The synthetic provider delay is a controlled workload input, not
a claim about live provider performance. Use the separate provider evaluation
fixtures to study provider coverage and observed latency.

## Reference run

[`benchmarks/baseline.json`](../benchmarks/baseline.json) records a repeated
reference run on the machine and Python version listed in the file. Its summary
reports central tendency and run-to-run spread; each individual sample is
retained so the reader can inspect outliers and confirm the workload digest.
In this reference, scheduler-only enrichment reached a median 1,418.8
indicators/second and persistence reached 92.9 indicators/second. The database
grew by 999,424 bytes (10.0 KB per indicator). Individual snapshot replay had
a median p50 of 1.14 ms. Reconstructing the 100-indicator investigation took a
median 184.2 ms at 543.0 indicators/second and returned 202 graph edges; the
bounded pivot-path query took 57.6 ms. The three-run spread is included in the
JSON report.

A profile of the earlier investigation replay found over 20,000 per-entity
relationship queries because each case indicator traversed the same shared
investigation neighborhood. Case replay now traverses from all indicator roots
together under one shared edge budget. On the same 100-indicator workload, this
reduced median replay time from 5.51 seconds to 184 ms (about 30 times faster)
while returning the same 202 edges with complete, untruncated state. Single-root
graph calls retain their existing traversal order and truncation behavior.

These local measurements are not a capacity guarantee. The difference between
scheduler-only and persisted throughput helps identify paths to profile; it
does not by itself justify weakening atomic persistence behavior. Rerun the
harness on target hardware before choosing storage optimizations.

SQLite serializes writes through the history store's lock, which keeps snapshot,
evidence, graph, and event updates consistent in one local transaction. The
benchmark reports persisted throughput separately from scheduler-only
throughput so this write path remains visible. The harness is measurement
evidence, not a gate with hardware-dependent pass/fail timing thresholds.
