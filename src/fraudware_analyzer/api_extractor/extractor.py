"""
API Extractor Module

This module extracts API calls from PE files and analyzes
them for suspicious patterns.
"""

from typing import Dict, List, Set, Any
import re


class APIExtractor:
    """
    Extracts and analyzes API calls from PE files.

    Identifies suspicious API usage patterns that may indicate
    malicious behavior.
    """

    # Suspicious API categories
    SUSPICIOUS_APIS = {
        "process_manipulation": [
            "CreateProcess",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "VirtualAllocEx",
            "SetWindowsHookEx",
            "CreateProcessInternalW",
        ],
        "registry_manipulation": [
            "RegCreateKey",
            "RegSetValue",
            "RegDeleteValue",
            "RegOpenKey",
            "RegCloseKey",
        ],
        "file_operations": [
            "CreateFile",
            "WriteFile",
            "ReadFile",
            "DeleteFile",
            "CopyFile",
            "MoveFile",
            "FindFirstFile",
            "FindNextFile",
        ],
        "network": [
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "InternetReadFile",
            "socket",
            "connect",
            "send",
            "recv",
            "WSAStartup",
        ],
        "encryption": [
            "CryptCreateHash",
            "CryptHashData",
            "CryptDecrypt",
            "CryptEncrypt",
            "CryptDeriveKey",
        ],
        "anti_debug": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugString",
            "DebugBreak",
        ],
        "keyboard_hook": [
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "GetAsyncKeyState",
            "GetKeyboardState",
        ],
        "service_manipulation": [
            "OpenSCManager",
            "CreateService",
            "StartService",
            "DeleteService",
            "ControlService",
        ],
    }

    # Known malicious API combinations
    MALICIOUS_SEQUENCES = {
        "keylogger": ["GetAsyncKeyState", "GetKeyboardState", "SetWindowsHookEx"],
        "process_injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "download": ["InternetOpen", "InternetConnect", "HttpSendRequest", "InternetReadFile"],
        "persistence": ["RegOpenKey", "RegSetValue", "RegCloseKey"],
        "clipboard": ["OpenClipboard", "GetClipboardData"],
    }

    def __init__(self):
        """Initialize the API extractor."""
        # Flatten suspicious APIs for quick lookup
        self.suspicious_api_set = set()
        for category, apis in self.SUSPICIOUS_APIS.items():
            self.suspicious_api_set.update(apis)

    def extract(self, pe_data: Dict[str, Any]) -> List[str]:
        """
        Extract API calls from PE data.

        Args:
            pe_data: Dictionary containing PE file information

        Returns:
            List of fully qualified API names (dll.function)
        """
        apis = []

        imports = pe_data.get("imports", [])
        for imp in imports:
            dll = imp.get("dll", "").lower()
            function = imp.get("function", "")

            # Normalize function name
            if function and not function.startswith("ord_"):
                # Remove A/W suffixes for comparison
                base_name = re.sub(r'[AW]$', '', function)
                apis.append(f"{dll}.{base_name}")

        return apis

    def get_suspicious_apis(self, apis: List[str]) -> List[str]:
        """
        Filter APIs to find only suspicious ones.

        Args:
            apis: List of API names

        Returns:
            List of suspicious API names
        """
        suspicious = []

        for api in apis:
            # Extract function name
            parts = api.split(".")
            if len(parts) >= 2:
                function = parts[1]

                # Check if function is in suspicious list
                if any(func.lower() in function.lower() for func in self.suspicious_api_set):
                    suspicious.append(api)

        return suspicious

    def categorize_apis(self, apis: List[str]) -> Dict[str, List[str]]:
        """
        Categorize APIs by their functionality.

        Args:
            apis: List of API names

        Returns:
            Dictionary mapping categories to API lists
        """
        categorized = {category: [] for category in self.SUSPICIOUS_APIS.keys()}

        for api in apis:
            parts = api.split(".")
            if len(parts) >= 2:
                function = parts[1].lower()

                for category, api_list in self.SUSPICIOUS_APIS.items():
                    if any(sus.lower() in function for sus in api_list):
                        categorized[category].append(api)

        return categorized

    def detect_sequences(self, apis: List[str]) -> Dict[str, bool]:
        """
        Detect known malicious API sequences.

        Args:
            apis: List of API names

        Returns:
            Dictionary mapping sequence names to detection status
        """
        detected = {}

        # Normalize API names for comparison
        api_functions = [api.split(".")[-1].lower() for api in apis]

        for sequence_name, required_apis in self.MALICIOUS_SEQUENCES.items():
            required_lower = [req.lower() for req in required_apis]
            detected[sequence_name] = all(
                any(req in api_func for api_func in api_functions)
                for req in required_lower
            )

        return detected

    def get_api_statistics(self, apis: List[str]) -> Dict[str, Any]:
        """
        Get statistics about API usage.

        Args:
            apis: List of API names

        Returns:
            Dictionary containing API statistics
        """
        # Count APIs by DLL
        dll_counts = {}
        for api in apis:
            parts = api.split(".")
            if len(parts) >= 2:
                dll = parts[0].lower()
                dll_counts[dll] = dll_counts.get(dll, 0) + 1

        # Get suspicious categories
        categorized = self.categorize_apis(apis)

        return {
            "total_apis": len(apis),
            "unique_apis": len(set(apis)),
            "dll_counts": dll_counts,
            "suspicious_by_category": {
                cat: len(apis_list)
                for cat, apis_list in categorized.items()
            },
        }
