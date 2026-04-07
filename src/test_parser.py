import sys
sys.path.insert(0, '.')
from parser.nmap_parser import NmapParser

if len(sys.argv) < 2:
    print("Uso: python test_parser.py <archivo.xml>")
    sys.exit(1)

parser = NmapParser(sys.argv[1])
data = parser.get_all_data()
print(f"Metadata: {data.metadata}")
print(f"Puertos abiertos: {len(data.open_ports)}")
print(f"OS matches: {len(data.os_matches)}")
print(f"Vulnerabilidades: {len(data.vulnerabilities)}")