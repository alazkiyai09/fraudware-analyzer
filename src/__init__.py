"""
Fraudware Analyzer: Static Analysis Framework for Banking Trojan Detection

This package provides tools for analyzing Windows executables to detect
and classify banking trojans and other malware.

Copyright (c) 2024 Ahmad Whafa Azka Al Azkiyai
Licensed under MIT License - see LICENSE file for details.

DISCLAIMER: This tool is for educational and research purposes only.
"""

__version__ = "0.1.0"
__author__ = "Ahmad Whafa Azka Al Azkiyai"
__email__ = "azka.alazkiyai@outlook.com"

from fraudware_analyzer.analyzer import Analyzer
from fraudware_analyzer.result import AnalysisResult

__all__ = ["Analyzer", "AnalysisResult", "__version__"]
