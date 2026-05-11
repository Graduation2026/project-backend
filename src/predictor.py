"""
predictor.py — ML inference module for vulnerability prediction.

Loads the trained TF-IDF vectorizer and Random Forest model once,
then exposes a simple predict() function for the API to call.
"""

import logging
from pathlib import Path

import joblib
import numpy as np

from .config import LABEL_MAP, MODEL_PATH, VECTORIZER_PATH

logger = logging.getLogger(__name__)


class VulnerabilityPredictor:
    """
    Singleton-style predictor that loads models on first use.

    Usage:
        predictor = VulnerabilityPredictor()
        result = predictor.predict("PUSH MOV SUB CALL ...")
    """

    def __init__(self):
        self._model = None
        self._vectorizer = None
        self._is_loaded = False

    def load_models(self):
        """Load the trained model and vectorizer from disk."""
        if self._is_loaded:
            return

        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model file not found: {MODEL_PATH}\n"
                f"Run 'python scripts/train_model.py' first to train the model."
            )
        if not VECTORIZER_PATH.exists():
            raise FileNotFoundError(
                f"Vectorizer file not found: {VECTORIZER_PATH}\n"
                f"Run 'python scripts/train_model.py' first to train the model."
            )

        logger.info("Loading ML models...")
        self._model = joblib.load(MODEL_PATH)
        self._vectorizer = joblib.load(VECTORIZER_PATH)
        self._is_loaded = True
        logger.info("✅ Models loaded successfully.")

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    def predict(self, features_text: str) -> dict:
        """
        Run vulnerability prediction on extracted features text.

        Args:
            features_text: Raw text content from a Ghidra features file.

        Returns:
            dict with keys:
                - prediction: "Safe" or "Vulnerable"
                - label: 0 or 1
                - confidence: float between 0 and 1
                - top_features: list of (feature_name, importance) tuples
        """
        if not self._is_loaded:
            self.load_models()

        # Vectorize the input text
        X = self._vectorizer.transform([features_text])

        # Get prediction and probability
        label = int(self._model.predict(X)[0])
        probabilities = self._model.predict_proba(X)[0]
        confidence = float(probabilities[label])

        # Extract top contributing features
        top_features = self._get_top_features(X)

        return {
            "prediction": LABEL_MAP[label],
            "label": label,
            "confidence": round(confidence, 4),
            "top_features": top_features,
        }

    def _get_top_features(self, X, top_n: int = 15) -> list[dict]:
        """
        Identify the top TF-IDF features present in this sample.

        We combine:
          - The TF-IDF weights for the input (which features are present)
          - The model feature importances (if available)

        The product tells us which features in THIS specific sample contributed
        most to the prediction.
        """
        feature_names = self._vectorizer.get_feature_names_out()
        
        # Get the TF-IDF values for this sample (sparse → dense)
        tfidf_values = X.toarray().flatten()

        if hasattr(self._model, 'feature_importances_'):
            importances = self._model.feature_importances_
            combined_scores = tfidf_values * importances
        else:
            # For ensemble models like VotingClassifier, fallback to highest TF-IDF presence
            combined_scores = tfidf_values

        # Get top N indices
        top_indices = np.argsort(combined_scores)[::-1][:top_n]

        top_features = []
        for idx in top_indices:
            if combined_scores[idx] > 0:
                top_features.append({
                    "feature": feature_names[idx],
                    "importance": round(float(combined_scores[idx]), 6),
                    "tfidf_weight": round(float(tfidf_values[idx]), 6),
                })

        return top_features


# ── Module-level singleton ──────────────────────────────────────────────────
# Import this instance in the API instead of creating a new one each time
predictor = VulnerabilityPredictor()
