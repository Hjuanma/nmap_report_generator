"""
Custom CVE enrichment using NVD API based on service CPEs.
Prioritizes services with higher impact potential.
"""

import nvdlib
from typing import List, Optional, Tuple
from models.data_models import Vulnerability, ScanData, Port
from utils.env_loader import get_nvd_api_key
from utils.impact_generator import generate_impact

# Priority scores for common high-impact services
SERVICE_PRIORITY = {
    # Web servers
    'http': 10,
    'https': 10,
    'apache': 10,
    'nginx': 10,
    'iis': 10,
    # Databases
    'mysql': 9,
    'postgresql': 9,
    'mongodb': 9,
    'redis': 9,
    'mssql': 9,
    # Remote access
    'ssh': 8,
    'telnet': 8,
    'rdp': 8,
    # Mail servers
    'smtp': 7,
    'imap': 7,
    'pop3': 7,
    # File sharing
    'ftp': 6,
    'smb': 6,
    'nfs': 6,
    # DNS
    'domain': 5,
    # Others default
}

def get_priority_score(port: Port) -> int:
    """Calculate a priority score for a port based on service name."""
    service_lower = (port.service_name or '').lower()
    # Check exact matches
    for key, score in SERVICE_PRIORITY.items():
        if key in service_lower:
            return score
    # Default low priority
    return 1

def build_cpe(service_name: Optional[str], product: Optional[str], version: Optional[str]) -> Optional[str]:
    """
    Build a CPE string from service product and version.
    Returns None if insufficient data.
    """
    if not product or not version:
        return None
    # Normalize product name: lowercase, replace spaces with underscores
    product_clean = product.lower().replace(' ', '_')
    # Remove common version suffixes
    version_clean = version.split()[0]  # take first part (e.g., "2.4.49" from "2.4.49 (Ubuntu)")
    return f"cpe:/a:{product_clean}:{version_clean}"

def enrich_with_cpes(data: ScanData, max_cpes: int = 10) -> ScanData:
    """
    For each open port with product and version, query NVD for CVEs.
    Prioritizes services based on impact (predefined scores).
    Only processes up to `max_cpes` most critical services.

    Args:
        data: ScanData object with open ports.
        max_cpes: Maximum number of CPEs to process (by priority).
    """
    api_key = get_nvd_api_key()
    if not api_key:
        print("⚠️ No NVD API key. Skipping CPE-based enrichment (would be too slow).")
        return data

    # Filter ports that have product and version
    eligible_ports = [p for p in data.open_ports if p.product and p.version]
    if not eligible_ports:
        print("ℹ️ No services with product+version found for CPE enrichment.")
        return data

    # Sort by priority score (higher first)
    eligible_ports.sort(key=get_priority_score, reverse=True)
    # Take only top max_cpes
    selected_ports = eligible_ports[:max_cpes]

    print(f"🔍 Processing up to {max_cpes} most critical services out of {len(eligible_ports)} eligible...")

    existing_cves = {v.cve for v in data.vulnerabilities}
    new_vulns = []
    delay = 0.6  # seconds between requests (safe with API key)

    for port in selected_ports:
        cpe = build_cpe(port.service_name, port.product, port.version)
        if not cpe:
            continue
        print(f"  Querying {cpe} (port {port.portid}, priority {get_priority_score(port)})...")
        try:
            results = nvdlib.searchCVE(cpeName=cpe, key=api_key, delay=delay)
        except Exception as e:
            print(f"    Error: {e}")
            continue

        for cve in results:
            if cve.id in existing_cves:
                continue
            # Extract CVSS v3.1 score (or fallback)
            cvss = None
            if hasattr(cve, 'v31score'):
                cvss = cve.v31score
            elif hasattr(cve, 'v30score'):
                cvss = cve.v30score
            elif hasattr(cve, 'v2score'):
                cvss = cve.v2score
            published = str(cve.published)[:10] if cve.published else None
            desc = cve.descriptions[0].value if cve.descriptions else ''
            impact = generate_impact(cvss, desc) if cvss else None

            vuln = Vulnerability(
                cve=cve.id,
                script="cpe_enricher",
                output_snippet=desc[:300],
                cvss_score=cvss,
                published_date=published,
                enriched_description=desc,
                solution_urls=[ref.url for ref in cve.references[:3] if 'patch' in ref.url.lower()],
                impact_description=impact
            )
            new_vulns.append(vuln)
            existing_cves.add(cve.id)

    data.vulnerabilities.extend(new_vulns)
    print(f"✅ Added {len(new_vulns)} new CVEs from CPE-based enrichment.")
    return data