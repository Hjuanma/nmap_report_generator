#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser.nmap_parser import NmapParser
from reporters.markdown_reporter import MarkdownReporter
from reporters.json_reporter import JsonReporter
from utils.enricher import enrich_vulnerabilities
from utils.env_loader import get_output_format

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <nmap_xml_file> [--json]")
        sys.exit(1)

    xml_path = sys.argv[1]
    output_json = '--json' in sys.argv

    print(f"📄 Parsing {xml_path}...")
    parser = NmapParser(xml_path)
    data = parser.get_all_data()

    # Enrich with NVD if possible
    data = enrich_vulnerabilities(data)

    if output_json:
        reporter = JsonReporter(data)
        with open('report.json', 'w', encoding='utf-8') as f:
            f.write(reporter.generate())
        print("✅ JSON report saved to report.json")
    else:
        reporter = MarkdownReporter(data)
        with open('report.md', 'w', encoding='utf-8') as f:
            f.write(reporter.generate())
        print("✅ Markdown report saved to report.md")

if __name__ == "__main__":
    main()