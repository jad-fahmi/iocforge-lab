# iocforge-lab

Threat intelligence enrichment tool for investigating IP addresses, domains, URLs, and file hashes using multiple intelligence sources.

## What it does

- detects IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256/SHA-512, emails, CVEs, and ASNs
- refangs defanged input like `evil[.]com` or `hxxp://`
- canonicalizes Unicode domains and URL hosts to IDNA ASCII without altering URL paths or queries
- queries several intel sources through pluggable connectors
- caches answers in sqlite so repeat lookups are cheap
- serves expired cache data only when a live provider fails, with explicit stale-cache metadata
- extracts IOCs from pasted analyst text, alerts, tickets, emails and logs
- scores results into an explainable verdict with evidence and counter-evidence
- applies local business context so internal assets and vendors are not overflagged
- prints as table, json, csv or a concise Markdown investigation report

## Sources

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Shodan
- GreyNoise
- RDAP (keyless domain and IP registration data)
- DNS (keyless A, AAAA, CNAME, MX, and NS resolution)
- crt.sh (keyless certificate-transparency metadata)
- URLhaus (authenticated malware URL lookup)
- ThreatFox (authenticated curated malware IOC lookup)
- MalwareBazaar (authenticated confirmed-malware file-hash lookup)
- CIRCL Hashlookup (keyless known-file metadata)
- urlscan.io (authenticated historical URL, domain, and IP scan metadata)

## Install

IOCForge requires Python 3.10 or later.

```
pip install -e .
```

## Config

Keys come from env vars or `~/.config/iocforge-lab/config.json`. Copy `.env.example` to `.env` and fill in whatever you have.

Providers can be disabled without removing their credentials:

```json
{"providers": {"shodan": {"enabled": false}}}
```

## Usage

```
ioc-enrich 8.8.8.8
ioc-enrich evil[.]com -f json
ioc-enrich -i iocs.txt -f jsonl
ioc-enrich -i iocs.txt -f csv
cat iocs.txt | ioc-enrich -i -
ioc-enrich 1.2.3.4 -s virustotal,abuseipdb
ioc-enrich --extract alert.txt --report markdown
ioc-enrich --extract ticket.txt --max-iocs 100 --fail-soft
ioc-enrich -i iocs.txt --fail-on-malicious
ioc-enrich --history evil.example --history-limit 20
ioc-enrich --config-diagnostics
ioc-enrich evil.example --explain
```

`--config-diagnostics` reports provider availability, enablement, and the
environment-variable name for each credential without printing credential values.
`--explain` renders the scoring decision, evidence, counter-evidence, blind
spots, reason codes, and recommended next action as JSON.

Indicators support analyst verdict overrides through the API. Overrides require
a reason, remain separate from source-derived scoring, and are recorded in the
indicator event timeline; clear them when the analyst decision no longer applies.

## Extraction

`--extract` reads messy SOC text instead of one-IOC-per-line input. It supports emails, SIEM alerts, firewall logs, proxy logs, EDR alerts, Slack messages and ticket text. It extracts IPs, domains, URLs, hashes, email addresses, CVEs and ASNs, while preserving line number, nearby source text, the original defanged form and the normalized IOC.

## Internal context

Pass one or more JSON context files with `--context`:

```json
{
  "allowlist": ["updates.vendor.example", "198.51.100.10"],
  "blocklist": ["bad.example"],
  "business_domains": ["example.com"],
  "cidrs": ["10.0.0.0/8", "198.51.100.0/24"]
}
```

Import asset inventory with `--asset-inventory assets.csv`. Recognized columns include `ip`, `host`, `domain`, `ioc`, `name`, `owner`, `tags`, and boolean tag columns such as `internal_asset`, `known_vendor`, `vpn_endpoint`, and `scanner_ip`.

Run the http api:

```
uvicorn ioc_enricher.api.app:app
```

Provider capabilities and credential availability are available at `GET /providers`.
New integrations should use the documented `/api/v1` endpoints: `POST /enrich`,
`POST /enrich/batch`, `POST /extract`, `POST /score/explain`, and `GET /providers`.

## Container deployment

The container also serves the lightweight analyst workbench at `http://localhost:8000/`.

Run the API with Docker Compose:

```shell
docker compose up --build
```

The service listens on port 8000, exposes `/health`, runs as a non-root user,
and persists enrichment history in the `iocforge-data` volume. Put provider keys
in a local `.env` file; it is not copied into the image.

Versioned API routes use an in-process per-peer rolling limit (default 60 requests
per minute; configure `IOC_API_RATE_LIMIT`, or set it to `0` to disable). A reverse
proxy should enforce client-IP limits when it terminates traffic before IOCForge.

## Releases and supply chain

Push a semantic version tag matching `pyproject.toml` (for example, `v0.1.0`) to
run the release workflow. It validates the project, builds wheel and source
artifacts, produces an SPDX SBOM, and attaches all three to a GitHub Release.
See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Interoperability

`POST /api/v1/interoperability/stix/export` enriches a batch and returns a STIX
2.1 bundle of supported IP, domain, URL, email, and file-hash Indicators. CVE
and ASN inputs are retained in IOCForge but omitted from STIX export until their
semantics can be represented without vendor-specific objects.

`POST /api/v1/interoperability/misp/export` returns an unpublished,
MISP-compatible event with mapped IOC attributes. It does not contact or publish
to a MISP server; review and import the JSON through your approved MISP workflow.

`GET /api/v1/investigations/{id}/report` renders a Markdown case report from
persisted investigation, indicator, enrichment, and timeline state.

`GET /api/v1/dashboard` supplies provider readiness, persisted verdict counts,
investigation lifecycle counts, and recent enrichment records for analyst UI clients.

## Scoring

Each source gets a weight. Shodan is informational and never moves the verdict. Buckets: clean, low, suspicious, malicious.

Results include `verdict`, `confidence`, `evidence`, `counter_evidence`, `no_data`, `errors`, `reason_codes`, and `recommended_action`. Older observations are discounted, while local allowlists, business domains, CIDR ranges and asset inventory tags can reduce false positives for known-safe assets.

## Notes

See [architecture](docs/architecture.md), [scoring](docs/scoring.md), and the
[threat model](docs/threat-model.md) for operating details.

## TODO

- [ ] passive dns source
- [ ] whois enrichment
- [ ] retry/backoff tuning per source
- [ ] output to a file instead of stdout
- [ ] dockerfile
