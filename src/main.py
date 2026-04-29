#!/usr/bin/env python3
# ============================================================
# Copyright (C) 2025 Hjuanma
#
# This source code is licensed under the Common Sense License
# (CSL) v1.1.
#
# You may obtain a copy of the license at:
# https://github.com/shmaplex/csl
#
# Large-Scale Commercial Users must comply with contribution
# requirements described in Section 8 of the License.
# ============================================================

"""
Nmap XML Report Generator - Main Entry Point
"""

import sys
import os
import argparse
import subprocess

# Add the src directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser.nmap_parser import NmapParser
from reporters.markdown_reporter import MarkdownReporter
from reporters.json_reporter import JsonReporter
from utils.enricher import enrich_vulnerabilities
from utils.file_utils import OutputResolver
from utils.cve_enricher import enrich_with_cpes

def main():
    parser = argparse.ArgumentParser(description='Generate report from Nmap XML.')
    parser.add_argument('xml_file', help='Path to Nmap XML file')
    parser.add_argument('-o', '--output', help='Output directory or file prefix (default: derived from XML name)')
    parser.add_argument('--json', action='store_true', help='Also generate JSON report')
    parser.add_argument('--max-cpes', type=int, default=10, help='Max number of CPEs to enrich (by priority)')
    parser.add_argument('--cpe-enrich', action='store_true', help='Enrich CVEs from service CPEs (requires API key)')
    parser.add_argument('--pdf', action='store_true', help='Convert Markdown report to PDF (requires pandoc)')
    args = parser.parse_args()

    print(f"📄 Parsing {args.xml_file}...")
    nmap_parser = NmapParser(args.xml_file)
    data = nmap_parser.get_all_data()

    # Enrich with NVD if API key is available
    data = enrich_vulnerabilities(data)

    if args.cpe_enrich:
        data = enrich_with_cpes(data, max_cpes=args.max_cpes)

    # Base output directory (default: "results")
    base_dir = "results"

    if args.output:
        # Check if output is absolute or explicitly relative (starts with /, ./, ../)
        if args.output.startswith(('/', './', '../')):
            # Use as-is (user wants full control)
            md_path = OutputResolver.resolve_path(args.output, is_json=False)
            json_path = OutputResolver.resolve_path(args.output, is_json=True) if args.json else None
            pdf_path = md_path.replace('.md', '.pdf') if args.pdf else None
        else:
            # Treat as relative to base_dir
            md_path = OutputResolver.resolve_path(os.path.join(base_dir, args.output), is_json=False)
            json_path = OutputResolver.resolve_path(os.path.join(base_dir, args.output), is_json=True) if args.json else None
            pdf_path = md_path.replace('.md', '.pdf') if args.pdf else None
    else:
        # No -o: save inside base_dir with default names
        md_name = OutputResolver.default_name_from_xml(args.xml_file, is_json=False)
        json_name = OutputResolver.default_name_from_xml(args.xml_file, is_json=True) if args.json else None
        md_path = OutputResolver.resolve_path(base_dir, is_json=False, default_name=md_name)
        json_path = OutputResolver.resolve_path(base_dir, is_json=True, default_name=json_name) if args.json else None

    
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

    # Convert to PDF if requested
    if args.pdf:
        try:
            pdf_path = md_path.replace('.md', '.pdf')
            subprocess.run([
                'pandoc', md_path,
                '-o', pdf_path,
                '--pdf-engine=xelatex',
                '-V', 'geometry:margin=1in',
                '-V', 'mainfont=DejaVu Sans',
                '-V', 'monofont=DejaVu Sans Mono'
            ], check=True, capture_output=True, text=True)
            print(f"✅ PDF report saved to {pdf_path}")
        except FileNotFoundError:
            print("⚠️ pandoc not found. Please install pandoc (https://pandoc.org/installing.html) to use --pdf.")
        except subprocess.CalledProcessError as e:
            print(f"❌ PDF conversion failed: {e.stderr}")

if __name__ == "__main__":
    main()