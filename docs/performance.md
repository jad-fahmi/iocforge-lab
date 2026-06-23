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
  --json-output benchmark-report.json
```

The report includes a digest of the generated IOC set and pivot-path fixture,
methodology version, runtime, platform, parameters, row counts, and measured timings. Timings are
specific to the machine and its current load; compare runs only with the same
parameters and environment. The synthetic provider delay is a controlled
workload input, not a claim about live provider performance. Use the separate
provider evaluation fixtures to study provider coverage and observed latency.
Percentiles use the nearest-rank method. The harness does not warm up the
scheduler before timing, so the first run includes executor startup.

## Reference run

[`benchmarks/baseline.json`](../benchmarks/baseline.json) records one reference
run on Windows 11, Python 3.13.2, and 8 logical CPUs. With 100 indicators, two
simulated providers, a 1 ms provider delay, and scheduler concurrency 8, it
measured 1,306.2 indicators/second without history persistence and 96.6
indicators/second with persistence. Peak observed task concurrency was 8 in the
first run and 6 in the persisted run. Linking 100 indicators to an investigation
took 0.69 seconds. Replaying 20 saved snapshots had a 0.439 ms p50 and 0.693 ms
p95. Direct pivot lookup took 1.173 ms; the bounded multi-hop query took 56.518
ms and expanded 404 graph edges. The database grew by 937,984 bytes, about 9.4
KB per indicator for this workload.

This is a single local sample, not a capacity guarantee. The large difference
between scheduler-only and persisted throughput makes SQLite transaction and
event/graph writes the next path to profile; it does not yet justify weakening
the current atomic persistence behavior. Rerun the harness on target hardware
before choosing storage optimizations.

SQLite serializes writes through the history store's lock, which keeps snapshot,
evidence, graph, and event updates consistent in one local transaction. The
benchmark reports persisted throughput separately from scheduler-only
throughput so this write path remains visible. The harness is measurement
evidence, not a gate with hardware-dependent pass/fail timing thresholds.
