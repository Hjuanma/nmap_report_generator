"""Data models placeholder."""
from dataclasses import dataclass
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

@dataclass
class ScanMetadata:
    scanner: str
    command: str
    start_time: str
    features: Dict[str, bool]

@dataclass
class ScanData:
    metadata: ScanMetadata
    open_ports: List[Port]
    os_matches: List[OSMatch]
    vulnerabilities: List[Vulnerability]