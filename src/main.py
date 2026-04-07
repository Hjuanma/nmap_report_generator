#!/usr/bin/env python3
"""
Nmap XML Report Generator - Main Entry Point
"""

import sys
import os
import argparse

# Add the src directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser.nmap_parser import NmapParser
from reporters.markdown_reporter import MarkdownReporter
from reporters.json_reporter import JsonReporter
from utils.enricher import enrich_vulnerabilities
from utils.file_utils import OutputResolver

def main():
    parser = argparse.ArgumentParser(description='Generate report from Nmap XML.')
    parser.add_argument('xml_file', help='Path to Nmap XML file')
    parser.add_argument('-o', '--output', help='Output directory or file prefix (default: derived from XML name)')
    parser.add_argument('--json', action='store_true', help='Also generate JSON report')
    args = parser.parse_args()

    print(f"📄 Parsing {args.xml_file}...")
    nmap_parser = NmapParser(args.xml_file)
    data = nmap_parser.get_all_data()

    # Enrich with NVD if API key is available
    data = enrich_vulnerabilities(data)

    # Determine output paths
    if args.output:
        md_path = OutputResolver.resolve_path(args.output, is_json=False)
        json_path = OutputResolver.resolve_path(args.output, is_json=True) if args.json else None
    else:
        md_path = OutputResolver.default_name_from_xml(args.xml_file, is_json=False)
        json_path = OutputResolver.default_name_from_xml(args.xml_file, is_json=True) if args.json else None

    # Write Markdown report
    md_reporter = MarkdownReporter(data)
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_reporter.generate())
    print(f"✅ Markdown report saved to {md_path}")

    # Write JSON report if requested
    if args.json and json_path:
        json_reporter = JsonReporter(data)
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(json_reporter.generate())
        print(f"✅ JSON report saved to {json_path}")

if __name__ == "__main__":
    main()