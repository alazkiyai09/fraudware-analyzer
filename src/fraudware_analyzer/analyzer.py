"""
Main Analyzer Module

This module provides the main Analyzer class that orchestrates
the malware analysis pipeline.
"""

import os
from typing import Optional, List, Dict, Any
from pathlib import Path

from fraudware_analyzer.pe_parser import PEParser
from fraudware_analyzer.api_extractor import APIExtractor
from fraudware_analyzer.string_analyzer import StringAnalyzer
from fraudware_analyzer.ml_classifier import MLClassifier
from fraudware_analyzer.yara_scanner import YARAScanner
from fraudware_analyzer.result import AnalysisResult


class Analyzer:
    """
    Main malware analysis orchestrator.

    Coordinates various analysis modules to provide comprehensive
    malware detection and classification.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        yara_rules_path: Optional[str] = None,
        enable_ml: bool = True,
        enable_yara: bool = True,
    ):
        """
        Initialize the analyzer.

        Args:
            model_path: Path to trained ML model
            yara_rules_path: Path to YARA rules directory
            enable_ml: Enable ML classification
            enable_yara: Enable YARA scanning
        """
        self.pe_parser = PEParser()
        self.api_extractor = APIExtractor()
        self.string_analyzer = StringAnalyzer()

        self.ml_classifier = None
        if enable_ml:
            self.ml_classifier = MLClassifier(model_path=model_path)

        self.yara_scanner = None
        if enable_yara and yara_rules_path:
            self.yara_scanner = YARAScanner(rules_path=yara_rules_path)

    def analyze(self, file_path: str) -> AnalysisResult:
        """
        Analyze a PE file for malware indicators.

        Args:
            file_path: Path to the file to analyze

        Returns:
            AnalysisResult object containing analysis results
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Initialize result
        result = AnalysisResult(file_path=file_path)

        # Parse PE file
        try:
            pe_data = self.pe_parser.parse(file_path)
            result.pe_info = pe_data
        except Exception as e:
            result.add_error(f"PE parsing failed: {str(e)}")
            return result

        # Extract API calls
        try:
            api_calls = self.api_extractor.extract(pe_data)
            result.api_calls = api_calls
            result.suspicious_apis = self.api_extractor.get_suspicious_apis(api_calls)
        except Exception as e:
            result.add_error(f"API extraction failed: {str(e)}")

        # Extract and analyze strings
        try:
            strings = self.string_analyzer.extract(file_path)
            result.strings = strings
            result.suspicious_strings = self.string_analyzer.get_suspicious_strings(strings)
        except Exception as e:
            result.add_error(f"String analysis failed: {str(e)}")

        # ML Classification
        if self.ml_classifier:
            try:
                classification = self.ml_classifier.classify(api_calls, strings)
                result.family = classification.get("family", "Unknown")
                result.confidence = classification.get("confidence", 0.0)
            except Exception as e:
                result.add_error(f"ML classification failed: {str(e)}")

        # YARA Scanning
        if self.yara_scanner:
            try:
                yara_matches = self.yara_scanner.scan(file_path)
                result.yara_matches = yara_matches
            except Exception as e:
                result.add_error(f"YARA scanning failed: {str(e)}")

        # Calculate risk score
        result.calculate_risk_score()

        return result

    def analyze_batch(
        self,
        file_paths: List[str],
        progress_callback: Optional[callable] = None,
    ) -> List[AnalysisResult]:
        """
        Analyze multiple files in batch.

        Args:
            file_paths: List of file paths to analyze
            progress_callback: Optional callback for progress updates

        Returns:
            List of AnalysisResult objects
        """
        results = []

        for i, file_path in enumerate(file_paths):
            try:
                result = self.analyze(file_path)
                results.append(result)
            except Exception as e:
                # Create error result
                error_result = AnalysisResult(file_path=file_path)
                error_result.add_error(f"Analysis failed: {str(e)}")
                results.append(error_result)

            if progress_callback:
                progress_callback(i + 1, len(file_paths))

        return results
