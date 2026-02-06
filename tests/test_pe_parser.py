"""
Tests for PE Parser module.
"""

import pytest
from fraudware_analyzer.pe_parser import PEParser


def test_parser_initialization():
    """Test that PE parser initializes correctly."""
    parser = PEParser()
    assert parser is not None


def test_calculate_hashes():
    """Test hash calculation."""
    parser = PEParser()
    # Create a test file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("test content")
        test_file = f.name

    try:
        hashes = parser._calculate_hashes(test_file)
        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha256"]) == 64
    finally:
        import os
        os.unlink(test_file)


def test_detect_packer():
    """Test packer detection."""
    parser = PEParser()

    # Test with known packer sections
    sections = [
        {"name": "UPX0", "entropy": 7.8},
        {"name": "UPX1", "entropy": 7.9},
    ]
    assert parser._detect_packer(sections) == True

    # Test without packer
    sections = [
        {"name": ".text", "entropy": 6.0},
        {"name": ".data", "entropy": 5.0},
    ]
    assert parser._detect_packer(sections) == False
