# NAGAMERAH

**Threat Intelligence Aggregator & IOC Enrichment CLI Tool**

NAGAMERAH is a Linux-based command-line tool for defensive cybersecurity analysis that aggregates threat intelligence from multiple sources to enrich, investigate, and assess Indicators of Compromise (IOCs).

It helps security analysts perform IOC reputation checks, gather threat intelligence, identify suspicious indicators, and generate structured investigation reports through a single CLI interface.

---

## Features

- **IOC Detection & Validation** — Automatically identifies IPv4, IPv6, domains, URLs, MD5, SHA-1, and SHA-256 hashes.
- **IOC Normalization** — Handles defanged indicators and normalizes input for analysis.
- **Threat Intelligence Integration** — Retrieves reputation data from VirusTotal and AbuseIPDB using your own API keys.
- **Local DNS Intelligence** — Performs DNS lookups for A, AAAA, MX, NS, and TXT records.
- **Threat Assessment** — Calculates a weighted reputation score and generates a verdict based on available evidence.
- **Caching & History** — Stores lookup results and investigation history using SQLite.
- **Bulk Analysis** — Processes multiple IOCs from a single input file.
- **Report Export** — Supports JSON, TXT, CSV, and HTML report formats.
- **Secure Configuration** — Prompts for API keys securely and stores configuration with restrictive file permissions.

---

## Supported IOC Types

| IOC Type | Description |
|---|---|
| IPv4 | IPv4 address |
| IPv6 | IPv6 address |
| Domain | Domain name |
| URL | Uniform Resource Locator |
| MD5 | 128-bit hash |
| SHA-1 | 160-bit hash |
| SHA-256 | 256-bit hash |

Intelligence availability and provider coverage depend on the IOC type and the capabilities of each integrated provider.

---

## Threat Intelligence Providers

| Provider | Intelligence |
|---|---|
| VirusTotal | File, domain, IP, and URL reputation, detection statistics, and threat intelligence |
| AbuseIPDB | IP reputation, abuse reports, and confidence of abuse |
| Local DNS | DNS records including A, AAAA, MX, NS, and TXT |

Provider availability and returned data depend on the IOC type, API access, service availability, and provider limitations.

---

## Installation

### Requirements

- Linux (Kali Linux, Debian, or Ubuntu)
- Python 3.10+
- Internet connection
- API keys for supported threat intelligence providers (optional, but recommended)

### Install from source

```bash
git clone https://github.com/Valdarey/nagamerah.git
cd NAGAMERAH

chmod +x install.sh
./install.sh
```

The installation script will handle the installation process and prepare NAGAMERAH for use.

---

### Development Installation

To install NAGAMERAH in a development environment:

```bash
git clone https://github.com/Valdarey/NAGAMERAH.git
cd NAGAMERAH

python3 -m venv .venv
source .venv/bin/activate

pip install -e '.[dev]'
```

---

## Configuration

NAGAMERAH supports API key configuration through its built-in configuration commands or environment variables.

### Configure API Keys

```bash
nagamerah config set vt_key
nagamerah config set abuseipdb_key
```

API keys are prompted interactively and input is hidden.

### Environment Variables

Alternatively, configure API keys using environment variables:

```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

### View Configuration

```bash
nagamerah config show
```

Configuration output masks sensitive credentials to prevent accidental exposure.

---

## Usage

### Single IOC Lookup

Analyze an IP address:

```bash
nagamerah lookup 8.8.8.8
```

Analyze a domain:

```bash
nagamerah lookup example.com
```

Analyze a file hash:

```bash
nagamerah lookup 44d88612fea8a8f36de82e1278abb02f
```

### JSON Output

```bash
nagamerah lookup example.com --format json
```

### Bulk IOC Analysis

Analyze multiple indicators from a file:

```bash
nagamerah bulk iocs.txt
```

Export bulk results to CSV:

```bash
nagamerah bulk iocs.txt --format csv --output report.csv
```

### System Diagnostics

Check the environment, dependencies, and configuration:

```bash
nagamerah doctor
```

### Investigation History

View previous IOC investigations:

```bash
nagamerah history
```

### Cache Management

View cache statistics:

```bash
nagamerah cache stats
```

### Compare Reports

Compare two previously generated reports:

```bash
nagamerah diff old.json new.json
```

---

## Output Formats

NAGAMERAH supports multiple report formats for analysis, documentation, and integration with other workflows.

| Format | Use Case |
|---|---|
| TXT | Human-readable terminal reports and documentation |
| JSON | Structured data, automation, and integration |
| CSV | Spreadsheet analysis and IOC tracking |
| HTML | Readable reports for investigation and presentation |

Example:

```bash
nagamerah lookup example.com --format json --output report.json
```

---

## Security & Privacy

NAGAMERAH is designed for defensive security analysis and IOC enrichment.

- API credentials are stored with restrictive file permissions.
- Sensitive configuration values are masked when displayed.
- IOC lookups may transmit submitted indicators to third-party intelligence providers.
- Avoid submitting sensitive internal, private, or confidential indicators without proper authorization.
- Provider results represent external intelligence and should be validated against additional evidence when necessary.

> A clean reputation result does not guarantee that an IOC is benign. The absence of detection is not equivalent to safety.

---

## Disclaimer

NAGAMERAH is an open-source defensive threat intelligence utility intended for security research, incident response, threat hunting, and educational purposes.

Threat intelligence results may be incomplete, outdated, or inaccurate. Verdicts generated by NAGAMERAH should not be treated as definitive conclusions without further investigation and contextual analysis.

Users are responsible for ensuring that their use of the tool complies with applicable laws, organizational policies, provider terms of service, and data-sharing requirements.

---

## Roadmap

Planned development may include:

- Additional threat intelligence providers
- Enhanced IOC correlation
- Improved threat context and evidence analysis
- Expanded report customization
- Investigation workflow improvements
- Additional automation capabilities

---

## License

This project is licensed under the **MIT License**.

---

**NAGAMERAH** — Enrich indicators. Investigate threats. Make evidence-driven decisions.
