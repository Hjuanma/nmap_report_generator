from models.data_models import ScanData, Vulnerability
from utils.nvd_api import get_cve_details
from utils.env_loader import get_nvd_api_key

def enrich_vulnerabilities(data: ScanData) -> ScanData:
    """Add NVD details to each vulnerability if API key is available."""
    api_key = get_nvd_api_key()
    if not api_key:
        print("ℹ️ No NVD API key provided. Skipping CVE enrichment.")
        return data

    print(f"🔍 Enriching {len(data.vulnerabilities)} CVEs with NVD data...")
    # With API key we can use 0.6s delay (safe limit)
    delay = 0.6
    for idx, vuln in enumerate(data.vulnerabilities):
        print(f"  [{idx+1}/{len(data.vulnerabilities)}] {vuln.cve}...")
        details = get_cve_details(vuln.cve, delay=delay)
        if details:
            vuln.cvss_score = details['cvss']
            vuln.published_date = details['published']
            vuln.enriched_description = details['description']
            vuln.solution_urls = details['solution_urls']
        else:
            vuln.cvss_score = None
            vuln.published_date = None
            vuln.enriched_description = None
            vuln.solution_urls = []
    print("✅ Enrichment completed.")
    return data