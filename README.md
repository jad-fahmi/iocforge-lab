# iocforge-lab

Threat intelligence enrichment tool for investigating IP addresses, domains, URLs, and file hashes using multiple intelligence sources.

## What it does

- detects the type of an indicator (ip, domain, url, hash)
- refangs defanged input like `evil[.]com` or `hxxp://`
- queries several intel sources through pluggable connectors
- caches answers in sqlite so repeat lookups are cheap
- scores results into a single verdict
- prints as table, json or csv

## Sources

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Shodan
- GreyNoise

## Install

```
pip install -e .
```

## Config

Keys come from env vars or `~/.config/iocforge-lab/config.json`. Copy `.env.example` to `.env` and fill in whatever you have.

## Usage

```
ioc-enrich 8.8.8.8
ioc-enrich evil[.]com -f json
ioc-enrich -i iocs.txt -f csv
cat iocs.txt | ioc-enrich -i -
ioc-enrich 1.2.3.4 -s virustotal,abuseipdb
```

Run the http api:

```
uvicorn ioc_enricher.api.app:app
```

## Scoring

Each source gets a weight. Shodan is informational and never moves the verdict. Buckets: clean, low, suspicious, malicious.

## Notes

## TODO

- [ ] passive dns source
- [ ] whois enrichment
- [ ] retry/backoff tuning per source
- [ ] output to a file instead of stdout
- [ ] dockerfile
