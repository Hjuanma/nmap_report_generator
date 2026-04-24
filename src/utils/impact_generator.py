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

def generate_impact(cvss_score: float, description: str) -> str:
    if cvss_score is None:
        return "No CVSS score available."
    desc_lower = description.lower()
    if cvss_score >= 9.0:
        base = "Critical: Attacker could gain complete control of the system remotely."
    elif cvss_score >= 7.0:
        base = "High severity: Attacker could execute arbitrary code or cause significant damage."
    elif cvss_score >= 4.0:
        base = "Medium severity: Attacker might cause limited impact or information disclosure."
    else:
        base = "Low severity: Attacker would have very limited impact."
    
    # Add specific details from keywords
    if "remote code execution" in desc_lower or "rce" in desc_lower:
        base += " Remote code execution possible."
    if "denial of service" in desc_lower or "dos" in desc_lower:
        base += " Could cause denial of service."
    if "privilege escalation" in desc_lower:
        base += " Could lead to privilege escalation."
    if "sql injection" in desc_lower:
        base += " SQL injection vulnerability could leak database contents."
    if "cross-site scripting" in desc_lower or "xss" in desc_lower:
        base += " Cross-site scripting (XSS) could allow session hijacking."
    if "buffer overflow" in desc_lower:
        base += " Buffer overflow could lead to arbitrary code execution."
    return base