# IOCForge

IOCForge is an open source workbench for investigating suspicious indicators. It collects threat intelligence from multiple sources, preserves the evidence behind each result, and gives analysts a place to review indicators in the context of an investigation.

The project began as a command-line enrichment tool. It is growing into a case-centered investigation workbench: the goal is to make it easy to move from an unstructured alert to a reviewable account of what is known, where that information came from, and what remains uncertain.

IOCForge is early-stage software. The enrichment engine, connectors, API, lightweight web interface, investigation records, and interoperability endpoints are implemented. A richer evidence graph and a polished end-to-end investigation experience are works in progress.

## Why IOCForge

An indicator lookup can return a pile of unrelated facts: one provider reports abuse, another has no data, DNS returns a current answer, and an older passive DNS observation points somewhere else. Turning those observations into a defensible decision is still the analyst's job.

IOCForge is designed to keep that reasoning inspectable. It distinguishes evidence from counter-evidence, reports missing data and provider errors, discounts older observations, and applies local business context. Analyst overrides are stored separately from source-derived scores and require a reason.

The intended workflow is to paste an alert or report, extract its indicators with their surrounding context, enrich them, and investigate the resulting evidence together in a case. Each conclusion should be traceable to its observations. A verdict is a useful summary; it is not a replacement for reviewing the evidence.

## Overview

IOCForge supports IPv4 and IPv6 addresses, domains, URLs, MD5/SHA-1/SHA-256/SHA-512 hashes, email addresses, CVEs, and ASNs. It refangs common defanged forms such as `evil[.]example` and `hxxp://`, and normalizes internationalized domain names to IDNA ASCII.

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

IOCForge records sourced, time-bounded IOC relationships from DNS, passive DNS, and certificate-transparency observations. Each provider-derived edge links to its supporting evidence observation. The API supports bounded graph traversal and time filtering; typed infrastructure entities and a graph-focused workbench remain in progress.

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

### Docker Compose

```shell
docker compose up --build
```

The service listens on port 8000, runs as a non-root user, and stores enrichment history in the `iocforge-data` volume. Provider credentials can be placed in a local `.env` file; the file is not copied into the image.

## Configuration

Credentials are read from environment variables or `~/.config/iocforge-lab/config.json`. Copy `.env.example` for local development and add only the credentials for providers you want to enable.

Providers can be disabled without deleting their credentials:

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
ioc-enrich --compare 17 24
```

`--replay` accepts the enrichment history ID shown by `--history` and outputs
the original and recalculated scoring traces without querying providers.
`--compare` accepts baseline and later snapshot IDs, then reports added and
removed observations, decision changes, replay status, and graph differences.

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
| `POST /api/v1/relationships` | Record an analyst relationship or one tied to a supporting observation |
| `GET /api/v1/indicators/{ioc}/graph?depth=2&as_of=...` | Traverse relationships with depth, edge, and time bounds |
| `GET /api/v1/investigations/{id}/report` | Render a Markdown case report |

Investigation routes support creating and updating cases, changing lifecycle state, reviewing their timeline, and applying indicator verdict overrides. The API also provides STIX and MISP import/export routes under `/api/v1/interoperability/`.

Versioned API routes use a per-peer rolling rate limit of 60 requests per minute by default. Configure `IOC_API_RATE_LIMIT` or set it to `0` to disable the in-process limit. If a reverse proxy terminates traffic in front of IOCForge, configure client-IP limits at the proxy as well.

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
- The browser workbench is lightweight and does not yet expose graph traversal, historical replay comparison, or typed infrastructure nodes.

See [`docs/threat-model.md`](docs/threat-model.md) for operating assumptions and security details.

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

IOCForge is under active development. The current release line is `0.1.x`; API and workbench details may change as the investigation model develops. The most important planned work is a complete sample investigation, a clear evidence timeline, and graph exploration that retains source provenance on every relationship.

Issues and pull requests are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

IOCForge is released under the MIT License. See [`LICENSE`](LICENSE).
