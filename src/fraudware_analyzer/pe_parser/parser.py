"""
PE File Parser Module

This module handles parsing of Windows PE (Portable Executable) files.
"""

import pefile
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path


class PEParser:
    """
    Parser for Windows PE files.

    Extracts structural information, imports, exports, sections,
    and other relevant data from PE files.
    """

    # Known packer signatures
    PACKER_SIGNATURES = {
        "UPX": ["UPX0", "UPX1", "UPX2"],
        "ASPack": [".aspack", ".adata"],
        "Themida": [".themida", ".winlice"],
        "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
        "PECompact": ["PEC2", "PECompact2"],
        "Armadillo": [".data", ".rsrc"],  # Simplified
    }

    # Suspicious section names
    SUSPICIOUS_SECTIONS = [
        ".rsrc",  # Sometimes used for code injection
        ".idata",
        ".edata",
        ".bss",
        ".tls",
    ]

    def __init__(self):
        """Initialize the PE parser."""
        pass

    def parse(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a PE file and extract relevant information.

        Args:
            file_path: Path to the PE file

        Returns:
            Dictionary containing PE file information
        """
        result = {
            "file_path": file_path,
            "file_name": Path(file_path).name,
        }

        try:
            pe = pefile.PE(file_path)

            # Calculate file hash
            result["hashes"] = self._calculate_hashes(file_path)

            # Extract basic info
            result["machine"] = self._get_machine_type(pe)
            result["is_dll"] = pe.is_dll()
            result["is_exe"] = pe.is_exe()
            result["is_64bit"] = pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_TYPE.PE32_PLUS

            # Extract timestamp
            if hasattr(pe.FILE_HEADER, "TimeDateStamp"):
                result["compile_timestamp"] = pe.FILE_HEADER.TimeDateStamp

            # Extract sections
            result["sections"] = self._extract_sections(pe)
            result["is_packed"] = self._detect_packer(result["sections"])

            # Extract imports
            result["imports"] = self._extract_imports(pe)

            # Extract exports
            result["exports"] = self._extract_exports(pe)

            # Check for anomalies
            result["anomalies"] = self._detect_anomalies(pe, result)

            pe.close()

        except pefile.PEFormatError:
            result["error"] = "Invalid PE file format"
        except Exception as e:
            result["error"] = f"Parsing error: {str(e)}"

        return result

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes."""
        hashes = {}

        with open(file_path, "rb") as f:
            data = f.read()

        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()

        return hashes

    def _get_machine_type(self, pe: pefile.PE) -> str:
        """Get machine type string."""
        machine_types = {
            0x14c: "IMAGE_FILE_MACHINE_I386",
            0x8664: "IMAGE_FILE_MACHINE_AMD64",
            0x1c0: "IMAGE_FILE_MACHINE_ARM",
            0xaa64: "IMAGE_FILE_MACHINE_ARM64",
        }
        return machine_types.get(pe.FILE_HEADER.Machine, "UNKNOWN")

    def _extract_sections(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Extract section information."""
        sections = []

        for section in pe.sections:
            section_info = {
                "name": section.Name.decode("utf-8", errors="ignore").strip("\x00"),
                "virtual_address": hex(section.VirtualAddress),
                "size": section.SizeOfRawData,
                "entropy": self._calculate_entropy(section),
                "characteristics": hex(section.Characteristics),
                "is_executable": bool(section.Characteristics & 0x20000000),
                "is_readable": bool(section.Characteristics & 0x40000000),
                "is_writable": bool(section.Characteristics & 0x80000000),
            }
            sections.append(section_info)

        return sections

    def _calculate_entropy(self, section) -> float:
        """Calculate entropy of a section."""
        try:
            data = section.get_data()
            if len(data) == 0:
                return 0.0

            # Count byte frequencies
            counts = [0] * 256
            for byte in data:
                counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)

            return entropy / 8.0  # Normalize to 0-1

        except Exception:
            return 0.0

    def _detect_packer(self, sections: List[Dict[str, Any]]) -> bool:
        """Detect if file is packed based on section names."""
        section_names = [s["name"] for s in sections]

        for packer, signatures in self.PACKER_SIGNATURES.items():
            if any(sig in section_names for sig in signatures):
                return True

        # Check for high entropy sections (possible packer)
        for section in sections:
            if section["entropy"] > 7.5 and section["is_executable"]:
                return True

        return False

    def _extract_imports(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Extract imported functions and DLLs."""
        imports = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")

            for imp in entry.imports:
                if imp.name:
                    imports.append({
                        "dll": dll_name,
                        "function": imp.name.decode("utf-8", errors="ignore"),
                        "ordinal": None,
                    })
                else:
                    imports.append({
                        "dll": dll_name,
                        "function": f"ord_{imp.ordinal}",
                        "ordinal": imp.ordinal,
                    })

        return imports

    def _extract_exports(self, pe: pefile.PE) -> List[str]:
        """Extract exported functions."""
        exports = []

        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="ignore"))

        return exports

    def _detect_anomalies(self, pe: pefile.PE, parsed_data: Dict) -> List[str]:
        """Detect anomalies in the PE file."""
        anomalies = []

        # Check for abnormal section count
        if len(parsed_data["sections"]) > 10:
            anomalies.append("High number of sections")

        # Check for unusual entry point
        try:
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in parsed_data["sections"]:
                va = int(section["virtual_address"], 16)
                size = section["size"]
                if va <= entry_point < va + size and section["name"] in [".rsrc", ".data"]:
                    anomalies.append("Entry point in data/resource section")
                    parsed_data["unusual_entry_point"] = True
        except Exception:
            pass

        # Check for high entropy sections
        for section in parsed_data["sections"]:
            if section["entropy"] > 7.5:
                anomalies.append(f"High entropy section: {section['name']}")

        return anomalies
