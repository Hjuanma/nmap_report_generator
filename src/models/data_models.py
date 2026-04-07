"""Data models placeholder."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class Port:
    portid: str
    protocol: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

@dataclass
class OSMatch:
    name: str
    accuracy: str

@dataclass
class Vulnerability:
    cve: str
    script: str
    output_snippet: str
    cvss_score: Optional[float] = None
    published_date: Optional[str] = None
    enriched_description: Optional[str] = None
    solution_urls: List[str] = field(default_factory=list)
    impact_description: Optional[str] = None

@dataclass
class ScanMetadata:
    scanner: str
    command: str
    start_time: str
    features: Dict[str, bool]

@dataclass
class HostInfo:
    status: str          # 'up', 'down'
    reason: str          # 'echo-reply', 'arp', etc.
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None

@dataclass
class ScanData:
    metadata: ScanMetadata
    open_ports: List[Port]
    os_matches: List[OSMatch]
    vulnerabilities: List[Vulnerability]
    host_info: HostInfo
