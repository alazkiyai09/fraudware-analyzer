"""
ML Classifier Module

This module provides machine learning-based classification
of malware families.
"""

import os
from typing import Dict, List, Any, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib


class MLClassifier:
    """
    Machine Learning classifier for malware family detection.

    Uses a Random Forest classifier to identify malware families
    based on extracted features.
    """

    # Known malware families
    FAMILIES = [
        "zeus",
        "spyeye",
        "carberp",
        "citadel",
        "dyre",
        "pony",
        "fareit",
        "lokibot",
        "wannacry",
        "petya",
        "unknown",
    ]

    def __init__(
        self,
        model_path: Optional[str] = None,
        n_estimators: int = 100,
        max_depth: Optional[int] = None,
    ):
        """
        Initialize the ML classifier.

        Args:
            model_path: Path to a pre-trained model
            n_estimators: Number of trees in Random Forest
            max_depth: Maximum depth of trees
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1,
        )
        self.label_encoder = LabelEncoder()
        self.is_trained = False

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def train(
        self,
        features: List[np.ndarray],
        labels: List[str],
    ) -> Dict[str, float]:
        """
        Train the classifier.

        Args:
            features: List of feature vectors
            labels: List of malware family labels

        Returns:
            Training metrics
        """
        # Encode labels
        y = self.label_encoder.fit_transform(labels)

        # Stack features
        X = np.vstack(features)

        # Train model
        self.model.fit(X, y)
        self.is_trained = True

        # Calculate metrics
        score = self.model.score(X, y)

        return {
            "train_accuracy": score,
            "n_samples": len(X),
        }

    def classify(
        self,
        api_calls: List[str],
        strings: List[str],
    ) -> Dict[str, Any]:
        """
        Classify a sample based on extracted features.

        Args:
            api_calls: List of API calls
            strings: List of extracted strings

        Returns:
            Classification result
        """
        if not self.is_trained:
            # Use heuristic-based classification
            return self._heuristic_classify(api_calls, strings)

        # Extract features
        features = self._extract_features(api_calls, strings)

        # Reshape for prediction
        X = features.reshape(1, -1)

        # Predict
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        # Decode label
        family = self.label_encoder.inverse_transform([prediction])[0]

        # Get confidence
        confidence = np.max(probabilities)

        return {
            "family": family,
            "confidence": confidence,
            "probabilities": dict(zip(
                self.label_encoder.classes_,
                probabilities.tolist()
            )),
        }

    def _heuristic_classify(
        self,
        api_calls: List[str],
        strings: List[str],
    ) -> Dict[str, Any]:
        """
        Heuristic-based classification when model is not trained.

        Args:
            api_calls: List of API calls
            strings: List of strings

        Returns:
            Classification result based on heuristics
        """
        api_lower = " ".join(api_calls).lower()
        text = " ".join(strings).lower()

        scores = {}

        # Zeus indicators
        if "internetopen" in api_lower and "httpsendrequest" in api_lower:
            scores["zeus"] = scores.get("zeus", 0) + 3
        if "getasynckeystate" in api_lower:
            scores["zeus"] = scores.get("zeus", 0) + 2

        # Banking trojan indicators
        if "getclipboarddata" in api_lower:
            scores["banking_trojan"] = scores.get("banking_trojan", 0) + 2

        # Ransomware indicators
        if "cryptencrypt" in api_lower or "cryptdecrypt" in api_lower:
            if "encrypt" in text or "decrypt" in text:
                scores["ransomware"] = scores.get("ransomware", 0) + 3

        # Keylogger indicators
        if "setwindowshookex" in api_lower or "getasynckeystate" in api_lower:
            scores["keylogger"] = scores.get("keylogger", 0) + 2

        # Return best match
        if scores:
            best_family = max(scores, key=scores.get)
            confidence = min(scores[best_family] / 5.0, 1.0)

            return {
                "family": best_family,
                "confidence": confidence,
                "method": "heuristic",
            }
        else:
            return {
                "family": "unknown",
                "confidence": 0.0,
                "method": "heuristic",
            }

    def _extract_features(
        self,
        api_calls: List[str],
        strings: List[str],
    ) -> np.ndarray:
        """
        Extract features from API calls and strings.

        Args:
            api_calls: List of API calls
            strings: List of strings

        Returns:
            Feature vector
        """
        features = []

        # API-based features
        features.append(len(api_calls))
        features.append(len(set(api_calls)))

        # Count API categories
        api_text = " ".join(api_calls).lower()

        categories = {
            "process": ["createprocess", "writeprocessmemory", "createmotethread"],
            "network": ["internetopen", "socket", "connect", "send"],
            "registry": ["regcreate", "regsetvalue", "regopen"],
            "file": ["createfile", "writefile", "deletefile"],
            "crypto": ["cryptcreatehash", "cryptencrypt", "cryptdecrypt"],
        }

        for category, keywords in categories.items():
            count = sum(1 for kw in keywords if kw in api_text)
            features.append(count)

        # String-based features
        features.append(len(strings))
        features.append(sum(len(s) for s in strings) / max(len(strings), 1))

        # Suspicious string indicators
        text = " ".join(strings).lower()
        features.append(1 if "http" in text else 0)
        features.append(1 if ".exe" in text else 0)
        features.append(1 if "password" in text else 0)

        return np.array(features, dtype=np.float32)

    def save_model(self, path: str) -> None:
        """
        Save the trained model to disk.

        Args:
            path: Path to save the model
        """
        model_data = {
            "model": self.model,
            "label_encoder": self.label_encoder,
            "is_trained": self.is_trained,
        }
        joblib.dump(model_data, path)

    def load_model(self, path: str) -> None:
        """
        Load a trained model from disk.

        Args:
            path: Path to the saved model
        """
        model_data = joblib.load(path)
        self.model = model_data["model"]
        self.label_encoder = model_data["label_encoder"]
        self.is_trained = model_data["is_trained"]
