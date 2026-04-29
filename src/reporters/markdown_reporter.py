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

from typing import Optional

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

        # ----- Executive Summary -----
        md += MD_TEMPLATES['executive_summary_header']
        md += MD_TEMPLATES['executive_summary_table']
        md += MD_TEMPLATES['executive_summary_row'].format(metric="Total open ports", value=str(len(self.data.open_ports)))

        if self.data.os_matches:
            os_names = ", ".join([os.name for os in self.data.os_matches[:3]])
            md += MD_TEMPLATES['executive_summary_row'].format(metric="Detected OS", value=os_names)
        else:
            md += MD_TEMPLATES['executive_summary_row'].format(metric="Detected OS", value="--NO SCANNED-- or not found")

        total_cves = len(self.data.vulnerabilities)
        md += MD_TEMPLATES['executive_summary_row'].format(metric="Total CVEs found", value=str(total_cves))

        # Overall Risk Rating
        risk = self._get_overall_risk_rating()
        md += MD_TEMPLATES['executive_summary_row'].format(metric="**Overall Risk Rating**", value=risk)

        # Severity breakdown
        sev_counts = self._severity_breakdown()
        md += MD_TEMPLATES['severity_breakdown_header']
        md += MD_TEMPLATES['severity_table_header']
        for sev in ["Critical", "High", "Medium", "Low", "Not scored"]:
            md += MD_TEMPLATES['severity_row'].format(severity=sev, count=sev_counts[sev])

        # Top 3 most critical CVEs
        top_cves = self._get_top_cves(3)
        if top_cves:
            md += "\n### Top 3 Most Critical CVEs\n\n"
            md += "| CVE | CVSS | Impact |\n"
            md += "|-----|------|--------|\n"
            for cve in top_cves:
                impact = cve.impact_description if cve.impact_description else "--"
                cvss = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "--"
                md += f"| {cve.cve} | {cvss} | {impact[:100]} |\n"

        # Recommendation
        md += "\n### Recommendation\n\n"
        md += self._get_recommendation() + "\n\n"

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
    
    def _get_severity(self, cvss: Optional[float]) -> str:
        if cvss is None:
            return "Not scored"
        if cvss >= 9.0:
            return "Critical"
        elif cvss >= 7.0:
            return "High"
        elif cvss >= 4.0:
            return "Medium"
        elif cvss > 0:
            return "Low"
        else:
            return "Not scored"

    def _severity_breakdown(self) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Not scored": 0}
        for vuln in self.data.vulnerabilities:
            sev = self._get_severity(vuln.cvss_score)
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _get_overall_risk_rating(self) -> str:
        """Return overall risk rating based on CVSS scores."""
        critical = any(v.cvss_score is not None and v.cvss_score >= 9.0 for v in self.data.vulnerabilities)
        high = any(v.cvss_score is not None and 7.0 <= v.cvss_score < 9.0 for v in self.data.vulnerabilities)
        if critical:
            return "CRITICAL"
        elif high:
            return "HIGH"
        elif any(v.cvss_score is not None for v in self.data.vulnerabilities):
            return "MEDIUM"
        else:
            return "LOW (no CVSS scores available)"

    def _get_top_cves(self, limit: int = 3) -> list:
        """Return top N CVEs sorted by CVSS score descending (only those with CVSS)."""
        scored = [v for v in self.data.vulnerabilities if v.cvss_score is not None]
        # Orden descendente, usando 0 como fallback (aunque nunca debería llegar)
        scored.sort(key=lambda x: x.cvss_score if x.cvss_score is not None else 0, reverse=True)
        return scored[:limit]

    def _get_recommendation(self) -> str:
        """Return actionable recommendation based on risk rating."""
        critical = any(v.cvss_score is not None and v.cvss_score >= 9.0 for v in self.data.vulnerabilities)
        high = any(v.cvss_score is not None and 7.0 <= v.cvss_score < 9.0 for v in self.data.vulnerabilities)
        if critical:
            return "**Immediate action required:** Patch or mitigate critical vulnerabilities as soon as possible."
        elif high:
            return "**Schedule remediation:** High severity vulnerabilities found. Plan fixes within 7 days."
        elif any(v.cvss_score is not None for v in self.data.vulnerabilities):
            return "**Review as scheduled:** Medium/low severity vulnerabilities. Address during normal maintenance."
        else:
            return "**No known vulnerabilities detected.** Keep security practices updated."