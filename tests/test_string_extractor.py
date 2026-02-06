"""
Tests for String Extractor module.
"""

import pytest
import tempfile
import os
from fraudware_analyzer.string_analyzer import StringExtractor


def test_extractor_initialization():
    """Test that string extractor initializes correctly."""
    extractor = StringExtractor()
    assert extractor is not None


def test_extract_strings():
    """Test string extraction from file."""
    extractor = StringExtractor()

    # Create a test file with known strings
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Hello World\x00\x00Test String\x00\x00Password123\x00")
        test_file = f.name

    try:
        strings = extractor.extract(test_file)
        assert len(strings) > 0
        assert "Hello World" in strings
        assert "Test String" in strings
    finally:
        os.unlink(test_file)


def test_get_suspicious_strings():
    """Test suspicious string detection."""
    extractor = StringExtractor()

    strings = [
        "https://malicious-site.com",
        "http://example.com/path",
        "192.168.1.1",
        "user@example.com",
        "C:\\Windows\\System32\\cmd.exe",
        "HKEY_LOCAL_MACHINE\\Software\\Test",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Bitcoin address
        "normal string",
        "test",
    ]

    suspicious = extractor.get_suspicious_strings(strings)
    assert len(suspicious) > 0

    types = {s["type"] for s in suspicious}
    assert "url" in types
    assert "ip" in types


def test_detect_malware_family():
    """Test malware family detection from strings."""
    extractor = StringExtractor()

    # Zeus-like strings
    strings = [
        "config.bin",
        "injects",
        "bankth",
    ]

    families = extractor.detect_malware_family(strings)
    assert "zeus" in families
    assert families["zeus"] > 0
