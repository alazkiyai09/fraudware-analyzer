"""
String Extractor Module

This module extracts and analyzes strings from PE files.
"""

import re
import regex
from typing import List, Dict, Any, Set


class StringExtractor:
    """
    Extracts and analyzes strings from PE files.

    Identifies suspicious strings including URLs, IPs,
    file paths, and other indicators.
    """

    # Minimum string length to extract
    MIN_LENGTH = 4

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        "password",
        "pass",
        "pwd",
        "login",
        "logon",
        "credential",
        "token",
        "cookie",
        "session",
        "bank",
        "account",
        "credit",
        "card",
        "cvv",
        "cvc",
        "expire",
        "bitcoin",
        "crypto",
        "wallet",
        "ransom",
        "decrypt",
        "encrypt",
        "inject",
        "hook",
        "keylog",
        "steal",
        "upload",
        "download",
        "cmd.exe",
        "powershell",
        "rundll32",
        "regsvr32",
    ]

    # Patterns for suspicious strings
    PATTERNS = {
        "url": re.compile(
            r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
            re.IGNORECASE
        ),
        "ip": re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            re.IGNORECASE
        ),
        "email": re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            re.IGNORECASE
        ),
        "guid": re.compile(
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
        ),
        "file_path": re.compile(
            r'[A-Z]:\\(?:[^\\]+\\)*[^\\]+',
            re.IGNORECASE
        ),
        "registry_key": re.compile(
            r'HKEY_[A-Z_]+\\(?:[^\\]+\\)*[^\\]+',
            re.IGNORECASE
        ),
        "bitcoin_address": re.compile(
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        ),
    }

    # Malware family-specific strings
    MALWARE_SIGNATURES = {
        "zeus": ["bankth", "injects", "config.bin", "botnet"],
        "spyeye": ["spyeye", "config.ini", "webinjects"],
        "carberp": ["carberp", "cabpacker"],
        "citadel": ["citadel", "citrix"],
        "pony": ["pony", "ponybot"],
    }

    def __init__(self, min_length: int = 4):
        """
        Initialize the string extractor.

        Args:
            min_length: Minimum string length to extract
        """
        self.min_length = min_length

    def extract(self, file_path: str) -> List[str]:
        """
        Extract printable strings from a file.

        Args:
            file_path: Path to the file

        Returns:
            List of extracted strings
        """
        strings = []

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Extract ASCII strings
            ascii_strings = self._extract_ascii_strings(data)
            strings.extend(ascii_strings)

            # Extract Unicode strings
            unicode_strings = self._extract_unicode_strings(data)
            strings.extend(unicode_strings)

            # Remove duplicates while preserving order
            seen = set()
            unique_strings = []
            for s in strings:
                if s not in seen:
                    seen.add(s)
                    unique_strings.append(s)

            return unique_strings

        except Exception as e:
            return []

    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        """Extract ASCII strings from binary data."""
        strings = []
        current_string = ""

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= self.min_length:
                    strings.append(current_string)
                current_string = ""

        return strings

    def _extract_unicode_strings(self, data: bytes) -> List[str]:
        """Extract UTF-16LE strings from binary data."""
        strings = []
        current_string = ""
        i = 0

        while i < len(data) - 1:
            if data[i] >= 32 and data[i] <= 126 and data[i + 1] == 0:
                current_string += chr(data[i])
                i += 2
            else:
                if len(current_string) >= self.min_length:
                    strings.append(current_string)
                current_string = ""
                i += 1

        return strings

    def get_suspicious_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """
        Identify suspicious strings from a list.

        Args:
            strings: List of strings to analyze

        Returns:
            List of suspicious string dictionaries
        """
        suspicious = []

        for string in strings:
            string_lower = string.lower()

            # Check for patterns
            for pattern_name, pattern in self.PATTERNS.items():
                if pattern.search(string):
                    suspicious.append({
                        "value": string,
                        "type": pattern_name,
                        "matched": True,
                    })
                    break

            # Check for keywords
            for keyword in self.SUSPICIOUS_KEYWORDS:
                if keyword in string_lower:
                    suspicious.append({
                        "value": string,
                        "type": "keyword",
                        "keyword": keyword,
                        "matched": True,
                    })
                    break

        return suspicious

    def detect_malware_family(self, strings: List[str]) -> Dict[str, int]:
        """
        Detect possible malware families from strings.

        Args:
            strings: List of strings to analyze

        Returns:
            Dictionary mapping family names to match counts
        """
        family_scores = {}

        text = " ".join(strings).lower()

        for family, signatures in self.MALWARE_SIGNATURES.items():
            score = 0
            for sig in signatures:
                if sig.lower() in text:
                    score += 1
            if score > 0:
                family_scores[family] = score

        return family_scores

    def get_string_statistics(self, strings: List[str]) -> Dict[str, Any]:
        """
        Get statistics about extracted strings.

        Args:
            strings: List of strings

        Returns:
            Dictionary containing string statistics
        """
        if not strings:
            return {
                "total": 0,
                "avg_length": 0,
                "max_length": 0,
            }

        lengths = [len(s) for s in strings]

        suspicious = self.get_suspicious_strings(strings)

        return {
            "total": len(strings),
            "avg_length": sum(lengths) / len(lengths),
            "max_length": max(lengths),
            "min_length": min(lengths),
            "suspicious_count": len(suspicious),
        }
