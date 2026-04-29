# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-04-07

### Added
- Initial release.
- Parse Nmap XML files.
- Host discovery (status, IP, MAC, hostname).
- Open ports table with total count and omitted notes.
- OS detection.
- Vulnerability extraction from `--script vuln`.
- NVD enrichment (CVSS, published date, description, solution links, impact text).
- CPE-based enrichment with prioritization (`--cpe-enrich`, `--max-cpes`).
- Markdown and JSON output.
- Custom output path (`-o`).
- Environment variable support (`.env`).
- Common Sense License (CSL).

### Fixed
- Type errors in `build_cpe`.
- Port table redundancy (single note).

### Security
- None.