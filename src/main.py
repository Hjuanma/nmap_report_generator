#!/usr/bin/env python3
import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser.nmap_parser import NmapParser
from reporters.markdown_reporter import MarkdownReporter
from reporters.json_reporter import JsonReporter

def sanitize_filename(name: str) -> str:
    """Replace invalid filename characters with underscore."""
    return re.sub(r'[\\/*?:"<>|]', '_', name)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <nmap_xml_file> [--json]")
        sys.exit(1)

    xml_path = sys.argv[1]
    output_json = '--json' in sys.argv

    # Parse XML
    parser = NmapParser(xml_path)
    data = parser.get_all_data()

    # Create results directory in project root (parent of src)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(project_root, 'results')
    os.makedirs(results_dir, exist_ok=True)

    # Get target name from XML
    target = parser.get_target()
    safe_target = sanitize_filename(target)

    if output_json:
        reporter = JsonReporter(data)
        output_file = os.path.join(results_dir, f"{safe_target}_report.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(reporter.generate())
        print(f"✅ JSON report saved to {output_file}")
    else:
        reporter = MarkdownReporter(data)
        output_file = os.path.join(results_dir, f"{safe_target}_report.md")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(reporter.generate())
        print(f"✅ Markdown report saved to {output_file}")

if __name__ == "__main__":
    main()