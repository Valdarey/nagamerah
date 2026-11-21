# NAGAMERAH v1.0.1
Threat Intelligence Aggregator & IOC Enrichment CLI Tool — defensive IOC reputation lookup. Linux only (Kali, Debian, Ubuntu).

## Features
- IOC validation/type detection (IPv4/IPv6/domain/URL/MD5/SHA1/SHA256), defang handling, normalization.
- VirusTotal and AbuseIPDB report lookups using your own API keys; local DNS A/AAAA/MX/NS/TXT.
- Weighted reputation score, verdict, SQLite cache/history, bulk input, JSON/TXT/CSV/HTML output.
- Config keys are prompted (hidden) and stored with restrictive permissions.

## Install
```bash
git clone https://github.com/Valdarey/NAGAMERAH.git && cd NAGAMERAH
chmod +x install.sh && ./install.sh
```
Development: `python3 -m venv .venv && source .venv/bin/activate && pip install -e '.[dev]'`

## Setup keys
`nagamerah config set vt_key` and `nagamerah config set abuseipdb_key`. Or set `VT_API_KEY` and `ABUSEIPDB_API_KEY`. `nagamerah config show` masks values.

## Usage
`nagamerah lookup 8.8.8.8` | `nagamerah lookup domain.tld --format json` | `nagamerah bulk iocs.txt --format csv --output report.csv` | `nagamerah doctor` | `nagamerah history` | `nagamerah cache stats` | `nagamerah diff old.json new.json`

Supported types and provider results depend on API coverage. No Detection is not equivalent to safe. IOC lookup shares submitted indicators with the configured third-party providers. Never submit sensitive/internal indicators without authorization.

See docs/ for architecture, installation, usage, provider and security details. MIT license; replace the copyright placeholder before distribution.
