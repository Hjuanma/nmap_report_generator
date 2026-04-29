# Nmap Report Generator

[![License](https://img.shields.io/badge/License-CSL-blue)](LICENSE.md)
[![Python](https://img.shields.io/badge/Python-3.7%2B-green)](https://www.python.org/)
[![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Generate a detailed **Markdown**, **JSON**, or **PDF** report from an Nmap XML scan.  
The report includes:

- **Executive Summary** – total open ports, detected OS, total CVEs, overall risk rating, severity breakdown, top 3 most critical CVEs, and an actionable recommendation.
- **Host Discovery** – status, IP, MAC, hostname.
- **Open Ports** – only ports with identifiable services (excludes `tcpwrapped`/`unknown`), with total count and omitted note.
- **OS Detection** – matched operating systems with accuracy.
- **Vulnerability Scan** – CVEs from `--script vuln`, enriched with NVD data (CVSS, publication date, description, solution links, impact text).
- **CPE‑based enrichment** – automatically builds CPEs from service versions and queries NVD for additional CVEs, with prioritization of high‑impact services.

## Features

- Parses any Nmap XML file (generated with `-oX`).
- Detects which scan options were enabled (version detection, OS detection, vuln scripts, aggressive scan, etc.).
- Shows `--NO SCANNED--` for data that was not requested.
- **Executive Summary** with overall risk rating (Critical, High, Medium, Low) and top 3 CVEs by CVSS.
- **Smart port table** – only shows ports with identifiable services.
- **Optional NVD enrichment** – for CVEs found in scripts (requires API key):
  - CVSS score (v3.1, v3.0, v2 fallback)
  - Publication date
  - Enriched description
  - Solution links (patches/updates)
  - **Impact description** – human‑readable text based on CVSS and keywords.
- **CPE‑based enrichment** – builds CPEs from service product/version and queries NVD for additional CVEs.
  - **Prioritization** – processes only the most critical services first (web servers, databases, remote access, etc.).
  - Configurable limit (`--max-cpes`).
- **PDF export** – convert the Markdown report to PDF (requires `pandoc`).
- **JSON output** – machine‑readable version with `--json`.
- **Smart output naming** – by default uses XML basename + `_report.md` (e.g., `scan.xml` → `scan_report.md`).
- **Custom output location** – with `-o` (directory or file path).
- **Environment variables** – `.env` support for `NVD_API_KEY`.
- Modular code (SOLID principles) – ready for further extensions.

## Requirements

- Python 3.7+
- `requests`
- `python-dotenv`
- `nvdlib` (for CPE‑based enrichment)
- `pandoc` (optional, for PDF export)

## Installation

```bash
git clone https://github.com/Hjuanma/nmap_report_generator.git
cd nmap_report_generator
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv nvdlib

# Optional: install pandoc for PDF export
sudo apt install pandoc   # Debian/Ubuntu/Kali
# or brew install pandoc on macOS
# or download from https://pandoc.org/installing.html
```

## Configuration (Optional but Recommended)

Create a `.env` file in the `src/` directory (or where you run the script) with your NVD API key:

```ini
NVD_API_KEY=your-api-key-here
```

You can obtain a free API key from [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key).  
Without an API key, CPE‑based enrichment will be skipped (NVD rate limits make it impractical).  
The script will still enrich CVEs from `--script vuln` if you provide the key.

## Usage

1. Run an Nmap scan with XML output (at least `-sV --script vuln` recommended):
   ```bash
   nmap -sV -O --script vuln -oX scan.xml <target>
   ```

2. Generate the report:
   ```bash
   cd src
   python main.py /path/to/scan.xml
   ```

### Output Naming

- **By default** (without `-o`), the report is named after the XML file:
  - `scan.xml` → `scan_report.md` (and `scan_report.json` if `--json` is used)
- Use `-o` or `--output` to specify a custom location:
  - `-o ./results/` → saves `report.md` and `report.json` inside the `results/` directory.
  - `-o ./my_report.md` → saves the Markdown report as `my_report.md` (JSON becomes `my_report.json` if `--json`).
  - `-o ./custom_prefix` → adds `.md` or `.json` automatically.

### Options

| Argument | Description |
|----------|-------------|
| `xml_file` | Path to Nmap XML file (required). |
| `-o, --output` | Output directory or file prefix. |
| `--json` | Also generate a JSON version of the report. |
| `--cpe-enrich` | Enable CPE‑based enrichment (requires API key). |
| `--max-cpes` | Max number of CPEs to process (by priority). Default: 10. |
| `--pdf` | Convert the Markdown report to PDF (requires `pandoc`). |

Examples:

```bash
# Basic report (no CPE enrichment)
python main.py scan.xml

# With CPE enrichment (process top 5 critical services)
python main.py scan.xml --cpe-enrich --max-cpes 5

# Save in a directory and also JSON
python main.py scan.xml -o ./reports/ --json

# Generate PDF report with full enrichment
python main.py scan.xml --cpe-enrich --pdf --json
```

## Project Structure

```
nmap_report_generator/
├── src/
│   ├── main.py                  # Entry point
│   ├── parser/
│   │   └── nmap_parser.py       # XML parsing (host, ports, OS, scripts)
│   ├── models/
│   │   └── data_models.py       # Dataclasses (Port, HostInfo, Vulnerability, etc.)
│   ├── reporters/
│   │   ├── markdown_reporter.py # Markdown report generation
│   │   └── json_reporter.py     # JSON report generation
│   ├── templates/
│   │   └── markdown_templates.py # Text templates (English)
│   └── utils/
│       ├── env_loader.py        # Loads .env variables
│       ├── nvd_api.py           # NVD API client (with caching)
│       ├── enricher.py          # Enriches CVEs from vuln scripts
│       ├── cve_enricher.py      # CPE‑based enrichment with prioritization
│       ├── impact_generator.py  # Generates human‑readable impact text
│       └── file_utils.py        # Output path resolution
├── .env                         # Optional: NVD_API_KEY
├── requirements.txt
└── README.md
```

## Example Report Snippet (with enrichment)

```markdown
## Executive Summary

| Metric | Value |
|--------|-------|
| Total open ports | 398 |
| Detected OS | Linux 4.19 |
| Total CVEs found | 42 |
| **Overall Risk Rating** | **CRITICAL** 🔴 |

### Vulnerabilities by Severity

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 12 |
| Medium | 18 |
| Low | 5 |
| Not scored | 4 |

### Top 3 Most Critical CVEs

| CVE | CVSS | Impact |
|-----|------|--------|
| CVE-2024-1234 | 9.8 | Critical: Remote code execution possible. |
| CVE-2023-5678 | 9.0 | Critical: Privilege escalation. |

### Recommendation

⚠️ **Immediate action required:** Patch or mitigate critical vulnerabilities as soon as possible.

## Host Discovery

- **Status:** up (reason: echo-reply)
- **IPv4:** 192.168.1.10
- **MAC:** 00:11:22:33:44:55
- **Hostname:** webserver

## Open Ports

**Total open ports:** 398

*Only ports with identifiable services are listed below. The remaining 394 ports were found open but the service could not be identified (tagged as 'tcpwrapped' or 'unknown').*

| Port | Protocol | Service | Product | Version |
|------|----------|---------|---------|---------|
| 53 | tcp | domain | NLnet Labs NSD | --NO SCANNED-- |
| 80 | tcp | http | Apache httpd | 2.4.49 |
| 443 | tcp | http | OpenResty web app server | --NO SCANNED-- |
```

## Limitations & Notes

The report automatically includes a "Limitations & Notes" section based on which flags were **not** used in the scan (e.g., missing `-p-`, `-sU`, `-sC`, etc.), so the reader understands what data might be incomplete.

## License

This project is licensed under the
[Common Sense License (CSL) v1.1](https://github.com/shmaplex/csl).

Free for individuals, nonprofits, researchers, and small businesses.
Large-Scale Commercial Users (revenue ≥ $10M/year) must contribute
back per Section 8 of the License.