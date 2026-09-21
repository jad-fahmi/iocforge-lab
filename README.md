# iocforge-lab

Threat intelligence enrichment tool for investigating IP addresses, domains, URLs, and file hashes using multiple intelligence sources.

## What it does

- detects IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256/SHA-512, emails, CVEs, and ASNs
- refangs defanged input like `evil[.]com` or `hxxp://`
- queries several intel sources through pluggable connectors
- caches answers in sqlite so repeat lookups are cheap
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

## Install

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
ioc-enrich -i iocs.txt -f csv
cat iocs.txt | ioc-enrich -i -
ioc-enrich 1.2.3.4 -s virustotal,abuseipdb
ioc-enrich --extract alert.txt --report markdown
ioc-enrich --extract ticket.txt --max-iocs 100 --fail-soft
ioc-enrich -i iocs.txt --fail-on-malicious
```

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
