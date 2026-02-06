"""
Tests for API Extractor module.
"""

import pytest
from fraudware_analyzer.api_extractor import APIExtractor


def test_extractor_initialization():
    """Test that API extractor initializes correctly."""
    extractor = APIExtractor()
    assert extractor is not None
    assert len(extractor.suspicious_api_set) > 0


def test_extract_apis():
    """Test API extraction from PE data."""
    extractor = APIExtractor()

    pe_data = {
        "imports": [
            {"dll": "kernel32.dll", "function": "CreateProcessA"},
            {"dll": "kernel32.dll", "function": "WriteProcessMemory"},
            {"dll": "user32.dll", "function": "MessageBoxA"},
        ]
    }

    apis = extractor.extract(pe_data)
    assert len(apis) == 3
    assert "kernel32.dll.createprocess" in apis


def test_get_suspicious_apis():
    """Test suspicious API filtering."""
    extractor = APIExtractor()

    apis = [
        "kernel32.dll.createprocess",
        "kernel32.dll.writeprocessmemory",
        "user32.dll.messagebox",
    ]

    suspicious = extractor.get_suspicious_apis(apis)
    assert len(suspicious) > 0
    assert "kernel32.dll.createprocess" in suspicious


def test_categorize_apis():
    """Test API categorization."""
    extractor = APIExtractor()

    apis = [
        "kernel32.dll.createprocess",
        "kernel32.dll.writeprocessmemory",
        "wininet.dll.internetopen",
    ]

    categorized = extractor.categorize_apis(apis)
    assert "process_manipulation" in categorized
    assert "network" in categorized


def test_detect_sequences():
    """Test malicious sequence detection."""
    extractor = APIExtractor()

    apis = [
        "kernel32.dll.virtualallocex",
        "kernel32.dll.writeprocessmemory",
        "kernel32.dll.createremotethread",
    ]

    sequences = extractor.detect_sequences(apis)
    assert "process_injection" in sequences
    assert sequences["process_injection"] == True
