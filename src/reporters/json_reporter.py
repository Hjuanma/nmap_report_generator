"""JSON reporter placeholder."""
import json
from models.data_models import ScanData

class JsonReporter:
    def __init__(self, data: ScanData):
        self.data = data

    def generate(self) -> str:
        # Convert dataclasses to dict recursively
        return json.dumps(self.data, default=lambda o: o.__dict__, indent=2)