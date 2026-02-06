"""
YARA Scanner Module

This module provides YARA rule scanning capabilities.
"""

import os
from typing import List, Dict, Any, Optional


class YARAScanner:
    """
    YARA rule scanner for malware signature matching.

    Uses YARA rules to match known malware signatures.
    """

    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize the YARA scanner.

        Args:
            rules_path: Path to YARA rules directory or file
        """
        self.rules_path = rules_path
        self.rules = None
        self.rules_compiled = False

        if rules_path:
            self.load_rules(rules_path)

    def load_rules(self, rules_path: str) -> bool:
        """
        Load YARA rules from a file or directory.

        Args:
            rules_path: Path to rules file or directory

        Returns:
            True if rules loaded successfully
        """
        try:
            import yara

            if os.path.isfile(rules_path):
                # Load single rule file
                self.rules = yara.compile(filepath=rules_path)
            elif os.path.isdir(rules_path):
                # Load all .yar files in directory
                rule_files = []
                for root, dirs, files in os.walk(rules_path):
                    for file in files:
                        if file.endswith(".yar") or file.endswith(".yara"):
                            rule_files.append(os.path.join(root, file))

                if rule_files:
                    # Compile rules from all files
                    filepaths = {f"rule_{i}": path for i, path in enumerate(rule_files)}
                    self.rules = yara.compile(filepaths=filepaths)

            self.rules_compiled = self.rules is not None
            return self.rules_compiled

        except ImportError:
            # YARA not available
            return False
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            return False

    def scan(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of match dictionaries
        """
        if not self.rules_compiled or self.rules is None:
            return []

        try:
            matches = self.rules.match(file_path)

            results = []
            for match in matches:
                result = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                }

                # Add matched strings if available
                if hasattr(match, 'strings') and match.strings:
                    result["matched_strings"] = [
                        {
                            "offset": s[0],
                            "identifier": s[1],
                            "data": s[2].hex() if isinstance(s[2], bytes) else str(s[2]),
                        }
                        for s in match.strings
                    ]

                results.append(result)

            return results

        except Exception as e:
            return [{"error": str(e)}]

    def is_available(self) -> bool:
        """Check if YARA scanner is available."""
        try:
            import yara
            return True
        except ImportError:
            return False
