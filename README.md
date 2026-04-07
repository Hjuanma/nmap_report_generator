# Nmap Report Generator

Generate a detailed Markdown report from an Nmap XML scan.  
The report includes open ports (only those with identifiable services), OS detection, vulnerabilities (CVEs) found by `--script vuln`, and a limitations section based on which Nmap flags were used.  
Optionally, it can enrich CVEs with CVSS scores, publication dates, and solution links from the NVD API.

## Features

- Parses any Nmap XML file (generated with `-oX`).
- Detects which scan options were enabled (version detection, OS detection, vuln scripts, etc.).
- Shows `--NO SCANNED--` for data that was not requested.
- Outputs a clean Markdown report in English.
- Extracts CVEs from script outputs.
- Enrich CVEs with NVD data (CVSS, published date, description, patch links) – requires API key.
- Improved port table – only shows ports with identifiable services (excludes `tcpwrapped`/`unknown`).
- Modular code ready for future extensions (JSON output, web interface, PDF export).

## Requirements

- Python 3.7+
- `requests`
- `python-dotenv` (for loading environment variables)

## Installation

```bash
git clone https://github.com/hjuanma/nmap_report_generator.git
cd nmap_report_generator
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv
```

## Configuration (Optional but Recommended for Enrichment)

Create a `.env` file in the `src/` directory (or in the root where you run the script) with your NVD API key:

```ini
NVD_API_KEY=your-api-key-here
OUTPUT_FORMAT=md   # md or json
```

You can obtain a free NVD API key from [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key).

If no API key is provided, the script will skip CVE enrichment and only show the original script output.

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

3. The report will be saved as `report.md` in the current directory.

### Options

- `--json` : Also generate a JSON version of the report (`report.json`).

## Project Structure

```
nmap_report_generator/
├── src/
│   ├── main.py                  # Entry point
│   ├── parser/
│   │   └── nmap_parser.py       # XML parsing logic
│   ├── models/
│   │   └── data_models.py       # Dataclasses for scan data
│   ├── reporters/
│   │   ├── markdown_reporter.py # Markdown generation
│   │   └── json_reporter.py     # JSON generation
│   ├── templates/
│   │   └── markdown_templates.py # Text templates (English)
│   └── utils/
│       ├── env_loader.py        # Loads .env variables
│       ├── nvd_api.py           # NVD API client (with caching)
│       └── enricher.py          # Enriches vulnerabilities with NVD data
├── .env                         # Optional: NVD_API_KEY, OUTPUT_FORMAT
├── requirements.txt
└── README.md
```

## Example Report Snippet (with Enrichment)

```markdown
## Open Ports

**Total open ports:** 398

*Only ports with identifiable services are listed below. The remaining 394 ports were found open but the service could not be identified (tagged as 'tcpwrapped' or 'unknown').*

| Port | Protocol | Service | Product | Version |
|------|----------|---------|---------|---------|
| 53 | tcp | domain | NLnet Labs NSD | --NO SCANNED-- |
| 80 | tcp | http-proxy | HAProxy http proxy | --NO SCANNED-- |
| 443 | tcp | http | OpenResty web app server | --NO SCANNED-- |
| 9100 | tcp | jetdirect | --NO SCANNED-- | --NO SCANNED-- |

## Vulnerability Scan (Script vuln)

| CVE | CVSS | Published | Script | Description / Solution |
|-----|------|-----------|--------|------------------------|
| CVE-2007-6750 | 7.5 | 2007-12-19 | http-slowloris-check | Slowloris DOS attack... **Solution:** [patch](https://github.com/...) |
```

## Limitations & Notes

The report automatically includes a "Limitations & Notes" section based on which flags were **not** used in the scan (e.g., missing `-p-`, `-sU`, `-sC`, etc.), so the reader understands what data might be incomplete.

## Future Enhancements

- Export to PDF via `pandoc`.
- Web interface (Django/Flask) for uploading XML and viewing reports.
- Support for multiple languages (Spanish, etc.) via template switching.
- Group vulnerabilities by severity.

## License

MIT
```