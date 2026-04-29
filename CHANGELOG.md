# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-04-20

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

## [1.1.0] - 2026-04-28

### Added
- Executive summary section with totals.
- Vulnerability severity grouping (Critical, High, Medium, Low, Not scored).