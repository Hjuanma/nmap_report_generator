# Nmap Report Generator

Generate a detailed Markdown report from an Nmap XML scan.  
The report includes open ports, OS detection, vulnerabilities (CVEs) found by `--script vuln`, and a limitations section based on which Nmap flags were used.

## Features

- Parses any Nmap XML file (generated with `-oX`).
- Detects which scan options were enabled (version detection, OS detection, vuln scripts, etc.).
- Shows `--NO SCANNED--` for data that was not requested.
- Outputs a clean Markdown report in English.
- Extracts CVEs from script outputs.
- Modular code ready for future extensions (JSON output, NVD enrichment, web interface).

## Requirements

- Python 3.7+
- `python-dotenv` (optional, for loading environment variables)

## Installation

```bash
git clone https://github.com/yourusername/nmap_report_generator.git
cd nmap_report_generator
python3 -m venv venv
source venv/bin/activate
pip install python-dotenv

## Usage

1. Run an Nmap scan with XML output:
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
│       └── env_loader.py        # Environment variables (optional)
├── .env                         # Optional: NVD_API_KEY, OUTPUT_FORMAT
├── requirements.txt
└── README.md
```

## Example Report Snippet

```markdown
## Open Ports

| Port | Protocol | Service | Product | Version |
|------|----------|---------|---------|---------|
| 22/tcp | tcp | ssh | OpenSSH | 7.4 --NO SCANNED-- |
| 80/tcp | tcp | http | Apache httpd | 2.4.49 |

## Vulnerability Scan (Script vuln)

| CVE | Script | Output snippet |
|-----|--------|----------------|
| CVE-2021-41773 | http-vuln-cve2021-41773 | HTTP request smuggling... |
```

## Future Enhancements

- Enrich CVEs with CVSS scores and solutions from NVD API.
- Export to PDF via `pandoc`.
- Web interface (Django/Flask) for uploading XML and viewing reports.
- Support for multiple languages (Spanish, etc.) via template switching.

## License

MIT
```