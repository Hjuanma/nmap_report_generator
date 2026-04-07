from models.data_models import ScanData
from templates.markdown_templates import MD_TEMPLATES

class MarkdownReporter:
    def __init__(self, data: ScanData):
        self.data = data
        self.features = data.metadata.features

    def _format_enabled_features(self) -> str:
        enabled = [k.replace('_', ' ').title() for k, v in self.features.items() if v]
        if not enabled:
            return "- No extra features (default scan only)\n"
        return ''.join([MD_TEMPLATES['enabled_feature'].format(feature=f) for f in enabled])

    def generate(self) -> str:
        md = MD_TEMPLATES['header'].format(
            scanner=self.data.metadata.scanner,
            command=self.data.metadata.command,
            start_time=self.data.metadata.start_time,
            enabled_features=self._format_enabled_features()
        )

        # Open ports
        md += MD_TEMPLATES['open_ports_header']
        all_ports = self.data.open_ports
        total_open = len(all_ports)
        
        # Count tcpwrapped ports
        tcpwrapped_count = sum(1 for p in all_ports if p.service_name == 'tcpwrapped')
        
        # Meaningful ports (not tcpwrapped and not unknown)
        meaningful_ports = [
            p for p in all_ports
            if p.service_name and p.service_name.lower() not in ['tcpwrapped', 'unknown']
        ]
        
        # Show summary
        md += f"**Total open ports:** {total_open}\n"
        if tcpwrapped_count > 0:
            md += f"*Note: {tcpwrapped_count} port(s) with 'tcpwrapped' (open but no service identified) are not shown in the table below.*\n"
        
        if total_open == 0:
            md += MD_TEMPLATES['no_open_ports']
        elif not meaningful_ports:
            md += "*No ports with identifiable services were found (all are 'tcpwrapped' or unknown).*\n"
        else:
            md += MD_TEMPLATES['open_ports_table']
            for p in meaningful_ports:
                service_name = p.service_name if p.service_name else 'unknown'
                if self.features['version_detection']:
                    product = p.product if p.product else '--NO SCANNED--'
                    version = p.version if p.version else '--NO SCANNED--'
                else:
                    product = '--NO SCANNED--'
                    version = '--NO SCANNED--'
                md += MD_TEMPLATES['open_ports_row'].format(
                    portid=p.portid,
                    protocol=p.protocol,
                    service_name=service_name,
                    product=product,
                    version=version
                )
            if len(meaningful_ports) < total_open:
                md += f"\n*... and {total_open - len(meaningful_ports)} additional open ports with no identifiable service omitted.*\n"
        # OS detection
        md += MD_TEMPLATES['os_detection_header']
        if self.features['os_detection']:
            if self.data.os_matches:
                md += MD_TEMPLATES['os_table_header']
                for os in self.data.os_matches:
                    md += MD_TEMPLATES['os_row'].format(name=os.name, accuracy=os.accuracy)
            else:
                md += MD_TEMPLATES['os_no_matches']
        else:
            md += MD_TEMPLATES['os_not_scanned']

        # Vulnerabilities
        md += MD_TEMPLATES['vuln_header']
        if self.features['vuln_scripts']:
            if self.data.vulnerabilities:
                md += MD_TEMPLATES['vuln_table_header']
                for i, v in enumerate(self.data.vulnerabilities[:20]):
                    md += MD_TEMPLATES['vuln_row'].format(
                        cve=v.cve,
                        script=v.script,
                        snippet=v.output_snippet[:100]
                    )
                if len(self.data.vulnerabilities) > 20:
                    md += MD_TEMPLATES['vuln_more'].format(remaining=len(self.data.vulnerabilities)-20)
            else:
                md += MD_TEMPLATES['vuln_no_found']
        else:
            md += MD_TEMPLATES['vuln_not_scanned']

        # Limitations
        md += MD_TEMPLATES['limitations_header']
        if not self.features['all_ports']:
            md += MD_TEMPLATES['limitation_all_ports']
        if not self.features['udp_scan']:
            md += MD_TEMPLATES['limitation_udp']
        else:
            # If UDP was scanned but no open ports, you could add a note (optional)
            pass
        if not self.features['traceroute']:
            md += MD_TEMPLATES['limitation_traceroute']
        if not self.features['default_scripts']:
            md += MD_TEMPLATES['limitation_default_scripts']

        md += MD_TEMPLATES['footer']
        return md