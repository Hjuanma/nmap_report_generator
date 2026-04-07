import requests
import time
from typing import Dict, Optional
from utils.env_loader import get_nvd_api_key

_cache = {}

def get_cve_details(cve_id: str, delay: float = 0.6) -> Optional[Dict]:
    """Fetch CVE details from NVD API. Returns dict with cvss, published, description, solution_urls."""
    if cve_id in _cache:
        return _cache[cve_id]

    api_key = get_nvd_api_key()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    if api_key:
        url += f"&apiKey={api_key}"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            if data.get('vulnerabilities'):
                vuln = data['vulnerabilities'][0]['cve']
                # English description
                desc = next((d['value'] for d in vuln.get('descriptions', []) if d['lang'] == 'en'), '')
                # CVSS (prefer v3.1, then v3.0, then v2)
                metrics = vuln.get('metrics', {})
                cvss = None
                if 'cvssMetricV31' in metrics:
                    cvss = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV30' in metrics:
                    cvss = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                elif 'cvssMetricV2' in metrics:
                    cvss = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                published = vuln.get('published', '')[:10]  # YYYY-MM-DD
                # References that might indicate patches
                refs = [ref['url'] for ref in vuln.get('references', []) if 'patch' in ref['url'].lower() or 'update' in ref['url'].lower()]
                result = {
                    'cvss': cvss,
                    'published': published,
                    'description': desc[:500] if desc else None,
                    'solution_urls': refs[:3]
                }
                _cache[cve_id] = result
                time.sleep(delay)  # Respect rate limits
                return result
    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
    return None