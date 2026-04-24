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

"""JSON reporter placeholder."""
import json
from models.data_models import ScanData

class JsonReporter:
    def __init__(self, data: ScanData):
        self.data = data

    def generate(self) -> str:
        # Convert dataclasses to dict recursively
        return json.dumps(self.data, default=lambda o: o.__dict__, indent=2)