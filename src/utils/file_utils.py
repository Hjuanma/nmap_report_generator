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

"""
File utilities for output path resolution and default naming.
"""

import os
from typing import Optional

class OutputResolver:
    """Handles output path resolution and default naming."""

    @staticmethod
    def resolve_path(base_path: str, is_json: bool = False, default_name: Optional[str] = None) -> str:
        """
        Resolve output path based on user-provided base_path.

        - If base_path is a directory (ends with / or exists as dir), save inside with default_name.
        - If base_path is a file path, use that (adjust extension for JSON).
        - If base_path is empty, return default_name.

        Args:
            base_path: User-provided output path (directory, file, or empty).
            is_json: Whether this is for a JSON file (affects extension logic).
            default_name: Fallback filename when base_path is a directory or empty.

        Returns:
            Absolute or relative path where the file should be written.
        """
        if not base_path:
            return default_name if default_name is not None else ('report.json' if is_json else 'report.md')

        base_path = os.path.normpath(base_path)

        # Directory case
        if base_path.endswith(os.sep) or os.path.isdir(base_path):
            os.makedirs(base_path, exist_ok=True)
            default = default_name if default_name is not None else ('report.json' if is_json else 'report.md')
            return os.path.join(base_path, default)
        else:
            # File path case
            dirname = os.path.dirname(base_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            if is_json:
                if base_path.endswith('.md'):
                    base_path = base_path[:-3] + '.json'
                elif not base_path.endswith('.json'):
                    base_path += '.json'
            else:
                if not base_path.endswith('.md'):
                    base_path += '.md'
            return base_path

    @staticmethod
    def default_name_from_xml(xml_path: str, is_json: bool = False) -> str:
        """
        Generate default report name from XML file name.

        Example: scan.xml -> scan_report.md (or scan_report.json)

        Args:
            xml_path: Path to the input XML file.
            is_json: If True, generate .json suffix; otherwise .md.

        Returns:
            Default filename (without directory).
        """
        base = os.path.splitext(os.path.basename(xml_path))[0]
        suffix = '_report.json' if is_json else '_report.md'
        return base + suffix