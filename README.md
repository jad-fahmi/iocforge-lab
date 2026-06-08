# ioc-enricher

Threat intelligence enrichment tool for investigating IP addresses, domains, URLs, and file hashes using multiple intelligence sources.

## What it does

- detects the type of an indicator (ip, domain, url, hash)
- refangs defanged input like `evil[.]com` or `hxxp://`
- queries several intel sources through pluggable connectors
- caches answers in sqlite so repeat lookups are cheap

## Sources

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Shodan
- GreyNoise

## Config

Keys come from env vars or `~/.config/ioc-enricher/config.json`. See `.env.example`.

## Usage

## TODO

- [ ] fan-out engine across sources
- [ ] verdict scoring
- [ ] json / table / csv output
- [ ] read iocs from a file or stdin
- [ ] optional http api
- [ ] more connector tests
