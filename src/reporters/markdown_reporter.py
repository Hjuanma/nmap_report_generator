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

        # ----- Host Discovery section -----
        md += MD_TEMPLATES['host_discovery_header']
        host = self.data.host_info
        md += MD_TEMPLATES['host_info_row'].format(
            status=host.status,
            reason=host.reason if host.reason else '--',
            ipv4=host.ipv4 if host.ipv4 else '--',
            ipv6=host.ipv6 if host.ipv6 else '--',
            mac=host.mac if host.mac else '--',
            hostname=host.hostname if host.hostname else '--'
        )

        # ----- Open ports (improved) -----
        md += MD_TEMPLATES['open_ports_header']
        total_open_ports = len(self.data.open_ports)
        md += f"**Total open ports:** {total_open_ports}\n\n"

        meaningful_ports = [
            p for p in self.data.open_ports
            if p.service_name and p.service_name.lower() not in ['tcpwrapped', 'unknown']
        ]

        if total_open_ports == 0:
            md += MD_TEMPLATES['no_open_ports']
        elif not meaningful_ports:
            md += "*No ports with identifiable services were found (all are 'tcpwrapped' or unknown).*\n"
        else:
            omitted = total_open_ports - len(meaningful_ports)
            if omitted > 0:
                md += f"*Only ports with identifiable services are listed below. The remaining {omitted} ports were found open but the service could not be identified (tagged as 'tcpwrapped' or 'unknown').*\n\n"
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

        # ----- OS detection -----
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

        # ----- Vulnerabilities (enriched if available) -----
        md += MD_TEMPLATES['vuln_header']
        if self.features['vuln_scripts']:
            if self.data.vulnerabilities:
                has_enrichment = any(v.cvss_score is not None for v in self.data.vulnerabilities)
                if has_enrichment:
                    md += "| CVE | CVSS | Published | Script | Description / Solution | Impact |\n"
                    md += "|-----|------|-----------|--------|------------------------|--------|\n"
                    for v in self.data.vulnerabilities[:20]:
                        cvss = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "--"
                        published = v.published_date if v.published_date else "--"
                        desc = v.enriched_description if v.enriched_description else v.output_snippet[:100]
                        if v.solution_urls:
                            sol_links = ", ".join([f"[patch]({url})" for url in v.solution_urls[:2]])
                            desc_solution = f"{desc}<br>**Solution:** {sol_links}"
                        else:
                            desc_solution = desc
                        impact = v.impact_description if v.impact_description else "--"
                        md += f"| {v.cve} | {cvss} | {published} | {v.script} | {desc_solution} | {impact} |\n"
                else:
                    md += MD_TEMPLATES['vuln_table_header']
                    for v in self.data.vulnerabilities[:20]:
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

        # ----- Limitations -----
        md += MD_TEMPLATES['limitations_header']
        if not self.features['all_ports']:
            md += MD_TEMPLATES['limitation_all_ports']
        if not self.features['udp_scan']:
            md += MD_TEMPLATES['limitation_udp']
        if not self.features['traceroute']:
            md += MD_TEMPLATES['limitation_traceroute']
        if not self.features['default_scripts']:
            md += MD_TEMPLATES['limitation_default_scripts']

        md += MD_TEMPLATES['footer']
        return md