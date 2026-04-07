import xml.etree.ElementTree as ET
import re
from typing import Dict, List
from models.data_models import ScanData, ScanMetadata, Port, OSMatch, Vulnerability

class NmapParser:
    def __init__(self, xml_path: str):
        self.tree = ET.parse(xml_path)
        self.root = self.tree.getroot()
        self.args = self.root.get('args', '')

    def _parse_features(self) -> Dict[str, bool]:
        args = self.args
        return {
            'version_detection': '-sV' in args or '-A' in args,
            'os_detection': '-O' in args or '-A' in args,
            'default_scripts': '-sC' in args or '-A' in args,
            'vuln_scripts': '--script' in args and 'vuln' in args,
            'udp_scan': '-sU' in args,
            'all_ports': '-p-' in args or '-p 1-65535' in args,
            'traceroute': '--traceroute' in args,
        }

    def get_metadata(self) -> ScanMetadata:
        return ScanMetadata(
            scanner=self.root.get('scanner', 'nmap'),
            command=self.args,
            start_time=self.root.get('startstr', 'unknown'),
            features=self._parse_features()
        )

    def get_open_ports(self) -> List[Port]:
        ports = []
        for port in self.root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                service = port.find('service')
                ports.append(Port(
                    portid=port.get('portid'),
                    protocol=port.get('protocol'),
                    service_name=service.get('name') if service is not None else None,
                    product=service.get('product') if service is not None else None,
                    version=service.get('version') if service is not None else None
                ))
        return ports

    def get_os_matches(self) -> List[OSMatch]:
        matches = []
        for osmatch in self.root.findall('.//osmatch'):
            matches.append(OSMatch(
                name=osmatch.get('name', ''),
                accuracy=osmatch.get('accuracy', '')
            ))
        return matches

    def get_vulnerabilities(self) -> List[Vulnerability]:
        vulns = []
        for script in self.root.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            if 'CVE-' in output:
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                for cve in set(cves):
                    vulns.append(Vulnerability(
                        cve=cve,
                        script=script_id,
                        output_snippet=output[:300].replace('\n', ' ')
                    ))
        return vulns

    def get_all_data(self) -> ScanData:
        return ScanData(
            metadata=self.get_metadata(),
            open_ports=self.get_open_ports(),
            os_matches=self.get_os_matches(),
            vulnerabilities=self.get_vulnerabilities()
        )