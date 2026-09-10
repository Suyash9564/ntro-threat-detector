"""
Scikit-Learn Isolation Forest Anomaly Detection Engine for Passive Telemetry.
Trains on a baseline of normal network behavior and scores real-time window feature vectors.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple, List
from app.features.extractor import WindowFeatureExtractor
from app.simulation.generator import TelemetryGenerator


class MLAnomalyDetector:
    """
    Lightweight, unsupervised machine learning anomaly detector using Isolation Forest.
    Observes statistical deviations from learned baseline without needing prior attack signatures.
    """
    def __init__(self, contamination: float = 0.04, random_state: int = 42):
        self.extractor = WindowFeatureExtractor()
        self.model = IsolationForest(
            n_estimators=120,
            contamination=contamination,
            max_samples=256,
            random_state=random_state,
            n_jobs=-1
        )
        self.is_trained = False
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        # Automatically fit model on synthetic normal traffic baseline
        self.train_baseline()

    def train_baseline(self, num_samples: int = 400) -> None:
        """Generate benign traffic windows to train the baseline Isolation Forest."""
        gen = TelemetryGenerator(seed=42)
        X_train = []

        all_features: Dict[str, List[float]] = {name: [] for name in self.extractor.FEATURE_NAMES}

        for _ in range(num_samples):
            # Normal window with 10 to 30 normal flows
            flows = [gen.generate_normal_flow() for _ in range(np.random.randint(12, 28))]
            feat_dict = self.extractor.extract_features(flows, window_duration=5.0)
            vec = self.extractor.to_vector(feat_dict)
            X_train.append(vec)
            for name in self.extractor.FEATURE_NAMES:
                all_features[name].append(feat_dict[name])

        X = np.array(X_train)
        self.model.fit(X)
        self.is_trained = True

        # Calculate normal baseline mean and standard deviations for explainability
        self.baseline_stats = {}
        for name in self.extractor.FEATURE_NAMES:
            vals = np.array(all_features[name])
            self.baseline_stats[name] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)) if np.std(vals) > 0 else 1.0,
                "p95": float(np.percentile(vals, 95))
            }

    def score(self, feature_dict: Dict[str, Any]) -> Tuple[bool, float, float, List[str]]:
        """
        Evaluate real-time window features.
        Returns:
            (is_anomaly: bool, raw_score: float, confidence: float, outlier_features: List[str])
        """
        if not self.is_trained:
            self.train_baseline()

        vec = self.extractor.to_vector(feature_dict).reshape(1, -1)
        # sklearn decision_function: lower means more abnormal (< 0 is typically anomaly)
        raw_score = float(self.model.decision_function(vec)[0])
        prediction = int(self.model.predict(vec)[0])  # -1 = anomaly, 1 = normal
        is_anomaly = (prediction == -1) or (raw_score < -0.02)

        # Convert raw decision score to calibrated confidence [0.0, 1.0]
        # In sklearn, typical normal scores are ~ +0.1 to +0.25, severe anomalies drop to -0.2 to -0.45
        if raw_score >= 0.08:
            confidence = max(0.05, round(0.15 - (raw_score * 0.4), 2))
        elif raw_score >= 0.0:
            confidence = round(0.40 - (raw_score * 3.0), 2)
        else:
            # Anomaly: scale -0.0 to -0.4 into 0.65 to 0.99
            norm = min(1.0, abs(raw_score) / 0.35)
            confidence = round(0.65 + (norm * 0.33), 2)

        # Identify which features deviated most significantly from learned normal distribution
        outlier_features = []
        for name in self.extractor.FEATURE_NAMES:
            val = feature_dict.get(name, 0.0)
            base = self.baseline_stats.get(name, {"mean": 0.0, "std": 1.0})
            z_score = abs(val - base["mean"]) / max(0.001, base["std"])
            if z_score >= 2.5:
                outlier_features.append(f"{name} (z-score: {z_score:.1f}, observed: {val}, baseline: {base['mean']:.1f})")

        return is_anomaly, round(raw_score, 4), confidence, outlier_features
