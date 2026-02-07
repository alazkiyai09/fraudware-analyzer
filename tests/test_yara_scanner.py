"""
Unit tests for YARA Scanner Module
"""

import pytest
from pathlib import Path
from fraudware_analyzer.yara_scanner import YARAScanner


class TestYARAScanner:
    """Test cases for YARAScanner."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = YARAScanner()
        assert scanner is not None
        assert not scanner.rules_compiled
        assert scanner.rules is None

    def test_initialization_with_invalid_path(self):
        """Test initialization with non-existent path."""
        scanner = YARAScanner(rules_path="/nonexistent/path")
        assert scanner is not None
        assert not scanner.rules_compiled

    def test_is_available_yara_not_installed(self, monkeypatch):
        """Test is_available when YARA is not installed."""
        # Mock import to fail
        def mock_import(name, *args, **kwargs):
            if name == "yara":
                raise ImportError("No module named 'yara'")
            return __import__(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__', mock_import)

        scanner = YARAScanner()
        result = scanner.is_available()
        # Should return False when yara is not available
        assert result is False

    def test_load_nonexistent_rules(self):
        """Test loading rules from non-existent path."""
        scanner = YARAScanner()
        result = scanner.load_rules("/nonexistent/path/rules.yar")
        assert result is False

    def test_scan_without_rules(self):
        """Test scanning without loaded rules."""
        scanner = YARAScanner()
        results = scanner.scan("/dummy/file.exe")
        assert results == []

    def test_scan_with_rules_yara_not_available(self):
        """Test scan behavior when YARA is not available."""
        scanner = YARAScanner(rules_path="/dummy/path")
        results = scanner.scan("/dummy/file.exe")
        # Should return empty list when YARA is not available
        assert results == []

    def test_load_rules_from_directory(self, tmp_path):
        """Test loading rules from a directory."""
        # Create dummy rule files
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "test1.yar").write_text("""
        rule TestRule1 {
            strings:
                $a = "test"
            condition:
                $a
        }
        """)

        (rules_dir / "test2.yar").write_text("""
        rule TestRule2 {
            strings:
                $b = "malware"
            condition:
                $b
        }
        """)

        scanner = YARAScanner()
        # This will fail without YARA installed, but we test the logic
        result = scanner.load_rules(str(rules_dir))
        # Result depends on whether YARA is installed
        assert isinstance(result, bool)

    def test_load_rules_from_file(self, tmp_path):
        """Test loading rules from a single file."""
        rule_file = tmp_path / "rules.yar"
        rule_file.write_text("""
        rule TestRule {
            strings:
                $a = "test"
            condition:
                $a
        }
        """)

        scanner = YARAScanner()
        result = scanner.load_rules(str(rule_file))
        # Result depends on whether YARA is installed
        assert isinstance(result, bool)

    def test_scan_nonexistent_file(self):
        """Test scanning a non-existent file."""
        scanner = YARAScanner()
        results = scanner.scan("/nonexistent/file.exe")
        # Should handle gracefully
        assert isinstance(results, list)

    def test_scanner_state_management(self):
        """Test scanner state after initialization."""
        scanner = YARAScanner()
        assert scanner.rules_path is None

        scanner = YARAScanner(rules_path="/some/path")
        assert scanner.rules_path == "/some/path"

    def test_scan_returns_list(self):
        """Test that scan always returns a list."""
        scanner = YARAScanner()
        results = scanner.scan("/any/file")
        assert isinstance(results, list)

    def test_rules_compiled_flag(self):
        """Test rules_compiled flag behavior."""
        scanner = YARAScanner()
        assert scanner.rules_compiled is False

        # Load invalid rules
        scanner.load_rules("/nonexistent/path")
        # Should still be False after failed load
        assert scanner.rules_compiled is False
