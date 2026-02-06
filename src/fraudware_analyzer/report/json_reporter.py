"""
JSON Reporter Module

This module generates JSON reports from analysis results.
"""

import json
from typing import Dict, Any
from fraudware_analyzer.result import AnalysisResult


class JSONReporter:
    """
    Generates JSON format reports from analysis results.
    """

    def generate(self, result: AnalysisResult, output_path: str) -> None:
        """
        Generate a JSON report.

        Args:
            result: AnalysisResult object
            output_path: Path to save the report
        """
        report_data = {
            "analysis_result": result.to_dict(),
            "detailed_info": {
                "pe_info": result.pe_info,
                "api_calls": result.api_calls[:100],  # Limit for readability
                "all_suspicious_apis": result.suspicious_apis,
                "suspicious_strings": result.suspicious_strings[:50],
            }
        }

        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
