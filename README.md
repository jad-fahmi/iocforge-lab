# IOCForge

IOCForge is an open source workbench for investigating suspicious indicators. It collects threat intelligence from multiple sources, preserves the evidence behind each result, and gives analysts a place to review indicators in the context of an investigation.

The project began as a command-line enrichment tool. It is growing into a case-centered investigation workbench: the goal is to make it easy to move from an unstructured alert to a reviewable account of what is known, where that information came from, and what remains uncertain.

IOCForge is early-stage software. The enrichment engine, connectors, API, lightweight web interface, investigation records, and interoperability endpoints are implemented. A richer evidence graph and a polished end-to-end investigation experience are works in progress.

## Why IOCForge

An indicator lookup can return a pile of unrelated facts: one provider reports abuse, another has no data, DNS returns a current answer, and an older passive DNS observation points somewhere else. Turning those observations into a defensible decision is still the analyst's job.

IOCForge is designed to keep that reasoning inspectable. It distinguishes evidence from counter-evidence, reports missing data and provider errors, discounts older observations, and applies local business context. Analyst overrides are stored separately from source-derived scores and require a reason.

The intended workflow is to paste an alert or report, extract its indicators with their surrounding context, enrich them, and investigate the resulting evidence together in a case. Each conclusion should be traceable to its observations. A verdict is a useful summary; it is not a replacement for reviewing the evidence.

## Overview

IOCForge supports IPv4 and IPv6 addresses, domains, URLs, MD5/SHA-1/SHA-256/SHA-512 hashes, email addresses, CVEs, and ASNs. It refangs common defanged forms such as `evil[.]example` and `hxxp://`, and normalizes internationalized domain names with non-transitional UTS #46 mapping to IDNA 2008 ASCII. This keeps names such as `faß.de` distinct from `fass.de`.

Indicators can be submitted individually, in batches, or extracted from analyst text. Results can be printed in a terminal, returned through the HTTP API, or retained as part of an investigation. SQLite caching makes repeated lookups cheaper; expired cached observations are labeled as stale when used after a provider failure.

### Current capabilities

- **Indicator parsing:** recognize supported IOC types, refang defanged input, and normalize domain names and URL hosts.
- **Text extraction:** extract indicators from SIEM and EDR alerts, firewall and proxy logs, tickets, email, Slack messages, and reports. Extraction results retain the line number, nearby text, original form, and normalized value.
- **Provider enrichment:** run keyless and authenticated connectors through a common interface, with provider selection and enablement controls.
- **Explainable scoring:** return a verdict, confidence, evidence, counter-evidence, missing data, errors, reason codes, and a recommended next action.
- **Local context:** use allowlists, blocklists, business domains, CIDRs, and asset inventory tags to reduce false positives for known infrastructure.
- **Investigation history:** persist investigations, indicator events, analyst overrides, and lifecycle changes; render a Markdown report from case data.
- **Interoperability:** import and export supported STIX 2.1 and MISP representations.
- **Multiple interfaces:** use the Python CLI, HTTP API, or the lightweight browser workbench served by the container.

## Design

IOCForge treats provider responses as observations, not as ground truth. Providers differ in coverage, freshness, and semantics, so their output is retained with source information and interpreted by the scoring layer. No data from a provider is not evidence that an indicator is clean.

The system is organized as a small Python application rather than a distributed platform. Connectors implement a shared interface; the enrichment engine coordinates them; scoring combines their results with local context; and the CLI, API, and web workbench expose the same core behavior.

```text
Analyst input
    │
    ├── indicator ───────────────┐
    └── alert / report → extract  │
                                ▼
                     normalize indicators
                                │
                  ┌─────────────┴──────────────┐
                  ▼                            ▼
          provider connectors           local context
                  │                            │
                  └─────────────┬──────────────┘
                                ▼
                   evidence and scoring
                                │
                 CLI / API / investigation
```

The browser workbench and API are backed by the same application services as the CLI. This keeps the scoring and provider behavior consistent across interfaces and makes local self-hosting practical.

### Scoring and context

Each source has a configured weight. Informational sources such as Shodan provide useful context without independently raising the verdict. Older observations are discounted. Allowlisted indicators, business domains, CIDR ranges, and asset inventory tags can reduce the chance that routine internal infrastructure is overflagged.

The output includes `verdict`, `confidence`, `evidence`, `counter_evidence`, `no_data`, `errors`, `reason_codes`, and `recommended_action`. See [`docs/scoring.md`](docs/scoring.md) for details.

Analysts can override a verdict through the API. An override requires a reason, is recorded in the indicator timeline, and remains distinct from the source-derived score. Clear an override when the analyst decision no longer applies.

### Investigation model

An investigation has a title, description, lifecycle state, indicators, enrichment history, and timeline. Cases can move through `open`, `triaged`, and `closed`. Changes to the case and analyst decisions are retained as events. A Markdown report can be generated from the persisted case state.

IOCForge records sourced, time-bounded IOC relationships from DNS, passive DNS, and certificate-transparency observations. Each provider-derived edge links to its supporting evidence observation. The API and browser workbench expose bounded typed-graph traversal, ranked pivots, temporal filtering, evidence timelines, deterministic replay, snapshot comparison, and investigation bundle inspection/export.

## Intelligence sources

Connectors are optional. Configure only the providers you intend to use; availability and returned data depend on provider credentials, rate limits, and coverage.

| Provider | Information |
| --- | --- |
| VirusTotal | Indicator reputation and observations |
| AbuseIPDB | IP abuse reports |
| AlienVault OTX | Community threat intelligence |
| Shodan | Internet-facing host information |
| GreyNoise | Internet scanner context |
| RDAP | Domain and IP registration data |
| DNS | A, AAAA, CNAME, MX, and NS records |
| CIRCL Passive DNS | Historical domain and IP observations |
| crt.sh | Certificate transparency metadata |
| URLhaus | Malware URL lookup |
| ThreatFox | Curated malware IOC lookup |
| MalwareBazaar | Confirmed malware hash lookup |
| CIRCL Hashlookup | Known-file metadata |
| urlscan.io | Historical URL, domain, and IP scan metadata |

The DNS, RDAP, passive DNS, certificate transparency, and Hashlookup integrations can provide data without API keys. Authenticated sources require credentials. Provider failures are returned as errors and do not silently become clean results.

## Installation

IOCForge requires Python 3.10 or later.

Install the CLI:

```shell
pip install -e .
ioc-enrich 8.8.8.8
```

Install the API dependencies and start the local service:

```shell
pip install -e ".[api]"
uvicorn ioc_enricher.api.app:app --reload
```

The API is available at `http://localhost:8000`. The container also serves the lightweight workbench at `/`.

The workbench's **Provider evaluation** section accepts an offline labeled JSON
fixture and displays coverage, failures, detection misses, classification
metrics, and reliability-weight candidates. Evaluation does not contact
providers or change scoring weights.

### Docker Compose

```shell
docker compose up --build
```

The service listens on `127.0.0.1:8000` on the host, runs as a non-root user, and stores enrichment history in the `iocforge-data` volume. The API has no built-in authentication, so keep the port on loopback unless a remote deployment adds an authenticated access-control boundary. Provider credentials can be placed in a local `.env` file; the file is not copied into the image.

## Configuration

Credentials are read from environment variables or `~/.config/iocforge-lab/config.json`. Copy `.env.example` for local development and add only the credentials for providers you want to enable.

Providers can be disabled without deleting their credentials:

```json
{
  "scheduler": {
    "max_concurrency": 8,
    "max_pending": 32,
    "include_optional": true
  },
  "providers": {
    "virustotal": {
      "enabled": true,
      "priority": 10,
      "concurrency": 2,
      "requests_per_window": 4,
      "window_seconds": 60,
      "timeout_seconds": 8,
      "retries": 2,
      "backoff_base_seconds": 1,
      "max_retry_after_seconds": 30
    },
    "crtsh": {"optional": true}
  }
}
```

Scheduler defaults retain current behavior: all providers are included, calls
have a 10-second per-request timeout and up to two retries, and quotas apply
only when configured. `max_concurrency` and `max_pending` bound work submitted
through one engine. Provider priority orders eligible queued work across
concurrent lookups, with FIFO ordering at the same priority;
`optional: true` sources can be omitted by setting
`scheduler.include_optional` to `false`. Per-provider quotas are enforced in
memory for the lifetime of the engine. See [architecture notes](docs/architecture.md)
for how retry delays and timeout bounds work.

```json
{"providers": {"shodan": {"enabled": false}}}
```

Check provider readiness without revealing credential values:

```shell
ioc-enrich --config-diagnostics
```

The diagnostic output reports whether a provider is available and enabled, along with the environment variable name used for its credential.

### Internal context

Pass one or more JSON context files with `--context`:

```json
{
  "allowlist": ["updates.vendor.example", "198.51.100.10"],
  "blocklist": ["bad.example"],
  "business_domains": ["example.com"],
  "cidrs": ["10.0.0.0/8", "198.51.100.0/24"]
}
```

Asset inventories can be imported with `--asset-inventory assets.csv`. Recognized columns include `ip`, `host`, `domain`, `ioc`, `name`, `owner`, `tags`, and boolean tag columns such as `internal_asset`, `known_vendor`, `vpn_endpoint`, and `scanner_ip`.

## CLI

```shell
# Enrich indicators
ioc-enrich 8.8.8.8
ioc-enrich evil[.]example -f json
ioc-enrich 1.2.3.4 -s virustotal,abuseipdb

# Read a list or standard input
ioc-enrich -i iocs.txt -f jsonl
ioc-enrich -i iocs.txt -f csv
cat iocs.txt | ioc-enrich -i -

# Extract indicators from analyst text and write a report
ioc-enrich --extract alert.txt --report markdown
ioc-enrich --extract ticket.txt --max-iocs 100 --fail-soft

# Explain a decision and inspect prior observations
ioc-enrich evil.example --explain
ioc-enrich --history evil.example --history-limit 20
ioc-enrich --replay 17
ioc-enrich --replay-investigation 3 --as-of 2026-01-01T12:00:00Z
ioc-enrich --compare-investigations 3 2026-01-01T12:00:00Z 2026-01-02T12:00:00Z
ioc-enrich --compare 17 24
ioc-enrich --bundle-export 3 --bundle-output case.iocforge
ioc-enrich --bundle-inspect case.iocforge
ioc-enrich --bundle-inspect case.iocforge --bundle-as-of 2026-01-01T12:00:00Z
ioc-enrich --bundle-inspect case.iocforge --bundle-compare-as-of 2026-01-01T12:00:00Z 2026-01-02T12:00:00Z
ioc-enrich --pivots evil.example --pivot-limit 20
ioc-enrich --pivot-paths evil.example --pivot-depth 4 --pivot-limit 20
ioc-enrich --evaluate-fixture tests/fixtures/provider-evaluation-v1.json
```

`--replay` accepts the enrichment history ID shown by `--history` and outputs
the original and recalculated scoring traces without querying providers.
`--replay-investigation` reconstructs investigation membership, metadata,
analyst state, each member's latest eligible enrichment, and the time-bounded
graph at the required `--as-of` timestamp. It reports incomplete historical
state when event integrity fails or legacy creation events lack initial fields.
`--compare-investigations` compares two such reconstructions and reports
membership, metadata, verdict, score, evidence, analyst-event, and graph-edge
changes without querying providers.
`--compare` accepts baseline and later snapshot IDs, then reports added and
removed observations, decision changes, replay status, and graph differences.
Bundles contain the case timeline, linked snapshots and evidence, graph edges,
scoring inputs, and event chains. `--bundle-inspect` validates checksums and
event integrity, replays supported snapshots from embedded evidence, and
compares adjacent snapshots and their time-bounded graph without providers.
`--bundle-as-of` reconstructs case metadata, membership, analyst state, saved
decisions, and graph state from the archive at a selected time;
`--bundle-compare-as-of` shows the changes between two such offline states.
These operations use the embedded archive data only.
`--pivots` ranks direct, currently valid graph neighbors by edge confidence and
entity type, and includes the supporting relationship provenance.
`--pivot-paths` ranks simple multi-hop paths to infrastructure entities and
retains the source, observation, and validity interval for each hop. The score
uses the weakest edge confidence, endpoint type weight, and a `1 / hops` depth
penalty; it is a transparent prioritization heuristic, not a probability.
`--evaluate-fixture` measures providers from a labeled JSON fixture without
making provider requests. See [provider evaluation methodology](docs/provider-evaluation.md).

### Reproducible T1/T2/T3 walkthrough

Generate a complete synthetic investigation without contacting providers or
opening IOCForge's normal history database:

```shell
python -m ioc_enricher.demo --output demo/t1-t2-t3.iocforge
```

The command writes a portable case bundle and prints the T1, T2, and T3
verdicts, decision traces, evidence and graph changes, replay checks, and bundle
integrity. T1 has conflicting stale intelligence and a URLhaus outage, keeping
the result at low risk. At T2, fresh provider classifications agree, URLhaus
recovers, and passive DNS, certificate, URL, and file-hash evidence raises the
verdict to malicious. The discovered URL and payload hash join the case at T2
and receive their own provider observations. At T3, VirusTotal reports benign,
OTX is stale, ThreatFox still reports malicious, URLhaus is unavailable again,
and passive DNS shows another infrastructure move. The verdict falls to
suspicious. T2 relationships expire before T3, so the bundle can demonstrate
both the historical graph and
the changed current graph offline. Timestamps are generated for each run; all
provider observations and relationships are synthetic. Inspect the archive with
`ioc-enrich --bundle-inspect demo/t1-t2-t3.iocforge` or upload it in the
workbench's **Inspect an .iocforge bundle** form to review both adjacent
snapshot comparisons and the T1-to-T3 case replay.

`--fail-on-malicious` returns a nonzero exit code when a malicious verdict is found. Use `-v` for operational logs and repeat it, or pass `--debug`, for connector-level debugging. Logs go to stderr so JSON, CSV, and report output remain machine-readable.

## HTTP API

Run the API with:

```shell
uvicorn ioc_enricher.api.app:app
```

The versioned API includes:

| Route | Purpose |
| --- | --- |
| `POST /api/v1/enrich` | Enrich one or more indicators |
| `POST /api/v1/enrich/batch` | Enrich a batch |
| `POST /api/v1/extract` | Extract indicators from text |
| `POST /api/v1/score/explain` | Explain a scoring result |
| `GET /api/v1/providers` | Inspect provider capability and readiness |
| `GET /api/v1/dashboard` | Read provider status, verdict counts, and recent records |
| `GET /api/v1/history` | Browse saved enrichment snapshots |
| `GET /api/v1/history/{enrichment_id}/replay` | Reproduce a saved decision from its stored evidence and scoring configuration |
| `GET /api/v1/history/{baseline_id}/compare/{comparison_id}` | Compare evidence, scoring decisions, and time-bounded graph state |
| `GET /api/v1/investigations/{id}/replay?as_of=...` | Reconstruct investigation state from event and evidence history at a selected time |
| `GET /api/v1/investigations/{id}/compare?baseline_as_of=...&comparison_as_of=...` | Explain membership, decision, evidence, analyst-state, and graph changes across two times |
| `GET /api/v1/indicators/{ioc}/integrity` | Verify the indicator event chain, evidence hashes, and snapshot links |
| `GET /api/v1/investigations/{id}/integrity` | Verify the investigation event chain and linked indicator evidence |
| `GET /api/v1/investigations/{id}/bundle` | Download a self-contained `.iocforge` archive |
| `POST /api/v1/investigations/bundles/inspect` | Load, validate, and replay an archive offline (`application/zip` body) |
| `POST /api/v1/investigations/bundles/inspect?as_of=...&baseline_as_of=...&comparison_as_of=...` | Reconstruct or compare whole-case states using only the uploaded bundle |
| `POST /api/v1/evaluation/run` | Run deterministic provider metrics from an offline labeled fixture |
| `POST /api/v1/relationships` | Record an analyst relationship or one tied to a supporting observation |
| `GET /api/v1/indicators/{ioc}/graph?depth=2&as_of=...&entity_type=...` | Traverse typed relationships with depth and time bounds |
| `GET /api/v1/indicators/{ioc}/pivots?limit=25&as_of=...` | Rank direct infrastructure pivots with edge provenance |
| `GET /api/v1/indicators/{ioc}/pivot-paths?depth=4&limit=25&as_of=...` | Rank bounded multi-hop pivot paths with per-hop provenance |
| `GET /api/v1/investigations/{id}/report` | Render a Markdown case report |

Investigation routes support creating and updating cases, changing lifecycle state, reviewing their timeline, and applying indicator verdict overrides. The API also provides STIX and MISP import/export routes under `/api/v1/interoperability/`.

Versioned API routes use a per-peer rolling rate limit of 60 requests per minute by default. Configure `IOC_API_RATE_LIMIT` or set it to `0` to disable the in-process limit. The peer table is capped at 10,000 entries by default (`IOC_API_RATE_LIMIT_CLIENTS`); additional peers share a bounded overflow bucket. If a reverse proxy terminates traffic in front of IOCForge, configure client-IP limits at the proxy as well.

## Interoperability

STIX export creates a STIX 2.1 bundle for supported IP, domain, URL, email, and file-hash indicators. CVEs and ASNs are retained in IOCForge but omitted from STIX export until they can be represented without vendor-specific objects.

STIX import validates supported Indicator patterns and extracts them locally. It does not evaluate compound expressions or trigger enrichment.

MISP export returns an unpublished MISP-compatible event with mapped IOC attributes. MISP import validates and extracts supported attributes locally. Neither operation contacts a MISP server or publishes data; review exported JSON and use your approved import workflow.

## Limitations and security

- Provider coverage varies. A lack of observations is not a benign verdict.
- Some providers require API keys, impose rate limits, or return only partial data.
- Enrichment sends submitted indicators to whichever external providers are enabled. Review provider terms and your organization's data handling requirements before submitting sensitive indicators.
- STIX support intentionally excludes compound pattern evaluation and unsupported indicator types.
- MISP interoperability produces or consumes local JSON; IOCForge does not publish directly to a MISP server.
- The browser workbench provides a bounded, time-filterable relationship graph. Select nodes to pivot and inspect each supporting edge in the provenance table; detailed replay and bundle validation payloads remain available in expandable structured views.

See [`docs/threat-model.md`](docs/threat-model.md) for operating assumptions and security details.

## Performance evidence

Run the offline benchmark harness to measure scheduler throughput, persisted
history growth, replay, and graph pivot lookup without contacting live
providers:

```shell
python -m benchmarks.run_benchmarks --indicators 100
```

See [`docs/performance.md`](docs/performance.md) for workload parameters and
interpretation.

## Development

Install development dependencies and run the project checks:

```shell
pip install -e ".[api,dev]"
pytest
ruff check .
mypy
```

The code is organized under `ioc_enricher/`:

```text
ioc_enricher/
├── api/                 # HTTP API and browser workbench
├── connectors/          # Threat intelligence and infrastructure sources
├── interoperability/    # STIX and MISP import/export
├── ioc/                 # Detection, normalization, and extraction
├── output/              # Table, JSON, CSV, JSONL, and Markdown renderers
├── cache.py             # SQLite response cache
├── context.py           # Local business and asset context
├── engine.py            # Enrichment orchestration
├── history.py           # Persisted investigations and indicator history
└── scoring.py            # Evidence scoring and recommended actions
```

See [`docs/architecture.md`](docs/architecture.md) for the request flow and component details. New integrations should implement the connector interface and register through the provider registry.

## Project status

IOCForge is under active development. The current release line is `0.1.x`; API and workbench details may change as the investigation model develops. A provider-free T1/T2/T3 walkthrough exercises conflicting and stale evidence, provider outages, changing infrastructure, historical replay, and offline comparison across both timeline stages. Continue expanding it with realistic multi-indicator campaign fixtures and more adversarial timeline variations.

Issues and pull requests are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

IOCForge is released under the MIT License. See [`LICENSE`](LICENSE).
