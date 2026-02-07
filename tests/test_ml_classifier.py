"""
Unit tests for ML Classifier Module
"""

import pytest
import numpy as np
from fraudware_analyzer.ml_classifier import MLClassifier


class TestMLClassifier:
    """Test cases for MLClassifier."""

    def test_initialization(self):
        """Test classifier initialization."""
        classifier = MLClassifier()
        assert classifier is not None
        assert not classifier.is_trained
        assert classifier.model is not None

    def test_heuristic_classify_zeus(self):
        """Test heuristic classification for Zeus trojan."""
        classifier = MLClassifier()

        # Zeus-like API calls
        api_calls = ["InternetOpenA", "HttpSendRequestA", "GetAsyncKeyState"]
        strings = ["httpsendrequest", "wininet"]

        result = classifier.classify(api_calls, strings)

        assert result is not None
        assert "family" in result
        assert "confidence" in result
        assert result["method"] == "heuristic"

    def test_heuristic_classify_ransomware(self):
        """Test heuristic classification for ransomware."""
        classifier = MLClassifier()

        # Ransomware-like patterns
        api_calls = ["CryptEncrypt", "CryptDecrypt"]
        strings = ["encrypt", "decrypt", "bitcoin", "ransom"]

        result = classifier.classify(api_calls, strings)

        assert result is not None
        assert "family" in result
        assert result["method"] == "heuristic"

    def test_heuristic_classify_keylogger(self):
        """Test heuristic classification for keylogger."""
        classifier = MLClassifier()

        # Keylogger-like patterns
        api_calls = ["SetWindowsHookEx", "GetAsyncKeyState"]
        strings = ["log", "key"]

        result = classifier.classify(api_calls, strings)

        assert result is not None
        assert "family" in result
        assert result["method"] == "heuristic"

    def test_heuristic_classify_unknown(self):
        """Test heuristic classification for unknown patterns."""
        classifier = MLClassifier()

        # No suspicious patterns
        api_calls = ["CreateFileA", "ReadFile"]
        strings = ["document", "text"]

        result = classifier.classify(api_calls, strings)

        assert result is not None
        assert result["family"] == "unknown"
        assert result["confidence"] == 0.0

    def test_extract_features(self):
        """Test feature extraction."""
        classifier = MLClassifier()

        api_calls = ["InternetOpenA", "HttpSendRequestA", "CreateFileA"]
        strings = ["http://example.com", "password", ".exe"]

        features = classifier._extract_features(api_calls, strings)

        assert features is not None
        assert isinstance(features, np.ndarray)
        assert len(features) > 0

    def test_feature_counts(self):
        """Test that feature counts are correct."""
        classifier = MLClassifier()

        api_calls = ["CreateProcess", "InternetOpen", "RegCreateKey"]
        strings = ["test"]

        features = classifier._extract_features(api_calls, strings)

        # Should have features for: total APIs, unique APIs, 5 categories
        # string count, avg string length, 3 string indicators
        assert len(features) == 12

    def test_train_and_predict(self):
        """Test training and prediction workflow."""
        classifier = MLClassifier(n_estimators=10)

        # Create dummy training data
        features = [
            np.array([10, 8, 2, 1, 0, 0, 1, 5, 100, 1, 0, 1]),
            np.array([5, 4, 0, 2, 1, 0, 0, 3, 50, 0, 1, 0]),
            np.array([20, 15, 5, 1, 2, 1, 3, 10, 80, 1, 0, 1]),
        ]
        labels = ["zeus", "pony", "unknown"]

        metrics = classifier.train(features, labels)

        assert "train_accuracy" in metrics
        assert "n_samples" in metrics
        assert classifier.is_trained

    def test_save_and_load_model(self, tmp_path):
        """Test model persistence."""
        classifier = MLClassifier(n_estimators=10)

        # Create dummy training data
        features = [
            np.array([10, 8, 2, 1, 0, 0, 1, 5, 100, 1, 0, 1]),
            np.array([5, 4, 0, 2, 1, 0, 0, 3, 50, 0, 1, 0]),
        ]
        labels = ["zeus", "pony"]

        classifier.train(features, labels)

        # Save model
        model_path = tmp_path / "model.pkl"
        classifier.save_model(str(model_path))

        assert model_path.exists()

        # Load model
        new_classifier = MLClassifier()
        new_classifier.load_model(str(model_path))

        assert new_classifier.is_trained

    def test_classify_with_trained_model(self):
        """Test classification with trained model."""
        classifier = MLClassifier(n_estimators=10)

        # Train model
        features = [
            np.array([10, 8, 2, 1, 0, 0, 1, 5, 100, 1, 0, 1]),
            np.array([5, 4, 0, 2, 1, 0, 0, 3, 50, 0, 1, 0]),
            np.array([20, 15, 5, 1, 2, 1, 3, 10, 80, 1, 0, 1]),
        ]
        labels = ["zeus", "pony", "unknown"]
        classifier.train(features, labels)

        # Classify
        api_calls = ["InternetOpenA", "HttpSendRequestA"]
        strings = ["http://malicious.com"]

        result = classifier.classify(api_calls, strings)

        assert result is not None
        assert "family" in result
        assert "confidence" in result
        assert 0 <= result["confidence"] <= 1

    def test_families_constant(self):
        """Test that FAMILIES constant contains expected families."""
        assert "zeus" in MLClassifier.FAMILIES
        assert "spyeye" in MLClassifier.FAMILIES
        assert "unknown" in MLClassifier.FAMILIES

    def test_empty_api_calls(self):
        """Test classification with empty API calls."""
        classifier = MLClassifier()

        result = classifier.classify([], [])

        assert result is not None
        assert result["family"] == "unknown"

    def test_feature_extraction_with_empty_data(self):
        """Test feature extraction with empty data."""
        classifier = MLClassifier()

        features = classifier._extract_features([], [])

        assert features is not None
        assert isinstance(features, np.ndarray)
