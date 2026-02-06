"""
Analysis Result Module

This module defines the AnalysisResult class that stores
and formats malware analysis results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


@dataclass
class AnalysisResult:
    """
    Stores the results of a malware analysis.

    Attributes:
        file_path: Path to the analyzed file
        file_hash: SHA256 hash of the file
        family: Detected malware family
        confidence: Classification confidence (0-1)
        risk_score: Calculated risk score (0-100)
        is_malicious: Whether the file is classified as malicious
        api_calls: List of extracted API calls
        suspicious_apis: List of suspicious API calls
        strings: List of extracted strings
        suspicious_strings: List of suspicious strings
        yara_matches: List of YARA rule matches
        pe_info: PE file information
        errors: List of errors during analysis
        analysis_time: Time taken for analysis
    """

    file_path: str
    file_hash: Optional[str] = None
    family: str = "Unknown"
    confidence: float = 0.0
    risk_score: int = 0
    is_malicious: bool = False
    api_calls: List[str] = field(default_factory=list)
    suspicious_apis: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    suspicious_strings: List[Dict[str, Any]] = field(default_factory=list)
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    pe_info: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    analysis_time: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_error(self, error: str) -> None:
        """Add an error to the result."""
        self.errors.append(error)

    def calculate_risk_score(self) -> None:
        """
        Calculate overall risk score based on various indicators.

        Score ranges from 0 (clean) to 100 (highly malicious).
        """
        score = 0

        # Suspicious APIs
        score += min(len(self.suspicious_apis) * 5, 30)

        # Suspicious strings
        score += min(len(self.suspicious_strings) * 3, 25)

        # YARA matches
        score += min(len(self.yara_matches) * 10, 30)

        # ML confidence
        if self.confidence > 0.7:
            score += 15

        # PE anomalies
        pe_score = self._calculate_pe_risk()
        score += min(pe_score, 20)

        self.risk_score = min(score, 100)
        self.is_malicious = self.risk_score >= 50

    def _calculate_pe_risk(self) -> int:
        """Calculate risk score from PE file anomalies."""
        if not self.pe_info:
            return 0

        score = 0

        # Check for packers
        if self.pe_info.get("is_packed"):
            score += 10

        # Check for suspicious sections
        suspicious_sections = ["UPX", "ASPack", "Themida", "VMProtect"]
        for section in self.pe_info.get("sections", []):
            if any(s in section.get("name", "") for s in suspicious_sections):
                score += 5

        # Check for unusual entry points
        if self.pe_info.get("unusual_entry_point"):
            score += 5

        return min(score, 20)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "family": self.family,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "is_malicious": self.is_malicious,
            "api_calls_count": len(self.api_calls),
            "suspicious_apis": self.suspicious_apis,
            "suspicious_strings_count": len(self.suspicious_strings),
            "yara_matches": self.yara_matches,
            "errors": self.errors,
            "timestamp": self.timestamp,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        return (
            f"AnalysisResult(file='{self.file_path}', "
            f"family='{self.family}', "
            f"confidence={self.confidence:.2f}, "
            f"risk={self.risk_score})"
        )
