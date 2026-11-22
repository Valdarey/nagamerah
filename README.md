<div align="center">

<img src="assets/logo.png" alt="NAGAMERAH logo" width="220">

# N A G A M E R A H

![Contributions](https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-c1121f?style=for-the-badge&labelColor=1a1a1f)
![Version](https://img.shields.io/badge/NAGAMERAH-v1.0.2-c1121f?style=for-the-badge&labelColor=1a1a1f)
![Python](https://img.shields.io/badge/PYTHON-3.10+-c1121f?style=for-the-badge&logo=python&logoColor=white&labelColor=1a1a1f)
![License](https://img.shields.io/badge/LICENSE-MIT-c1121f?style=for-the-badge&labelColor=1a1a1f)

</div>

NAGAMERAH is a powerful open-source tool that focuses on defensive threat intelligence, making it ideal for quickly enriching and assessing Indicators of Compromise (IOCs). It aggregates reputation data from multiple sources into a single CLI, so analysts can investigate faster and make evidence-driven decisions.

## Key features

- **Subcommands:** `lookup`, `bulk`, `config`, `history`, `cache`, `diff`, `doctor`
- **IOC Detection:** Auto-detects IPv4, IPv6, domain, URL, MD5, SHA-1, and SHA-256
- **Normalization:** Handles defanged indicators (`hxxp://`, `[.]`) and normalizes input
- **Intelligence:** VirusTotal, AbuseIPDB, and local DNS records (A, AAAA, MX, NS, TXT)
- **Assessment:** Weighted reputation score with an evidence-based verdict
- **Storage:** SQLite-backed caching and investigation history
- **Bulk Mode:** Analyze many IOCs from a single input file
- **Output:** TXT / JSON / CSV / HTML reports, report comparison with `diff`
- **Security:** Hidden API key prompts, restrictive file permissions, masked config output

---

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Supported IOC Types](#supported-ioc-types)
- [Threat Intelligence Providers](#threat-intelligence-providers)
- [Output Formats](#output-formats)
- [Security & Privacy](#security--privacy)
- [Disclaimer](#disclaimer)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

**Requirements**

- Linux (Kali Linux, Debian, or Ubuntu)
- Python 3.10+
- Internet connection
- API keys for supported providers (optional, but recommended)

**Install from source**

```bash
git clone https://github.com/Valdarey/NAGAMERAH.git
cd NAGAMERAH

chmod +x install.sh
./install.sh
```

**Development installation**

```bash
git clone https://github.com/Valdarey/NAGAMERAH.git
cd NAGAMERAH

python3 -m venv .venv
source .venv/bin/activate

pip install -e '.[dev]'
```

---

## Configuration

### Configure API keys

```bash
nagamerah config set vt_key
nagamerah config set abuseipdb_key
```

Keys are prompted interactively and input is hidden.

### Environment variables

```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

### View configuration

```bash
nagamerah config show
```

Sensitive credentials are masked in the output.

---

## Usage

```text
nagamerah <command> [options]
```

| Command | Description |
|---|---|
| `lookup <ioc>` | Enrich and assess a single IOC |
| `bulk <file>` | Analyze multiple IOCs from a file |
| `config set/show` | Manage API keys and configuration |
| `history` | View previous investigations |
| `cache stats` | View cache statistics |
| `diff <old> <new>` | Compare two generated reports |
| `doctor` | Check environment, dependencies, and configuration |

### Single IOC lookup

```bash
# IP address
nagamerah lookup 8.8.8.8

# Domain
nagamerah lookup example.com

# File hash
nagamerah lookup 44d88612fea8a8f36de82e1278abb02f
```

### JSON output

```bash
nagamerah lookup example.com --format json
```

### Bulk IOC analysis

```bash
nagamerah bulk iocs.txt
nagamerah bulk iocs.txt --format csv --output report.csv
```

### Diagnostics, history, cache, and diff

```bash
nagamerah doctor
nagamerah history
nagamerah cache stats
nagamerah diff old.json new.json
```

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

## Output Formats

| Format | Use Case |
|---|---|
| TXT | Human-readable terminal reports and documentation |
| JSON | Structured data, automation, and integration |
| CSV | Spreadsheet analysis and IOC tracking |
| HTML | Readable reports for investigation and presentation |

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

- Additional threat intelligence providers
- Enhanced IOC correlation
- Improved threat context and evidence analysis
- Expanded report customization
- Investigation workflow improvements
- Additional automation capabilities

---

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Open a pull request

---

## License

This project is licensed under the **MIT License**.

<div align="center">

**NAGAMERAH** — Enrich indicators. Investigate threats. Make evidence-driven decisions.

</div>
