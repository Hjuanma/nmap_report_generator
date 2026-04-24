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

"""Environment loader placeholder."""
import os
from dotenv import load_dotenv

load_dotenv()

def get_nvd_api_key() -> str:
    return os.getenv('NVD_API_KEY', '')

def get_output_format() -> str:
    return os.getenv('OUTPUT_FORMAT', 'md')