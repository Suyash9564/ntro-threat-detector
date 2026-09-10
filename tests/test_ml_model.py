import pytest
from app.simulation.generator import TelemetryGenerator
from app.features.extractor import WindowFeatureExtractor
from app.models.anomaly_detector import MLAnomalyDetector

def test_ml_anomaly_detector_training():
    detector = MLAnomalyDetector()
    assert detector.is_trained is True
    assert len(detector.baseline_stats) == len(detector.extractor.FEATURE_NAMES)

def test_ml_anomaly_detector_scoring():
    detector = MLAnomalyDetector()
    gen = TelemetryGenerator()
    extractor = WindowFeatureExtractor()

    # Normal flows should have higher decision score (closer to benign)
    normal_flows = [gen.generate_normal_flow() for _ in range(15)]
    normal_feats = extractor.extract_features(normal_flows, 5.0)
    _, norm_score, norm_conf, _ = detector.score(normal_feats)

    # Attack flows (e.g. DDoS) should produce a lower decision score / high anomaly confidence
    ddos_flows = gen.generate_ddos_flows(count=200)
    ddos_feats = extractor.extract_features(ddos_flows, 5.0)
    is_anomaly, ddos_score, ddos_conf, outliers = detector.score(ddos_feats)

    assert ddos_score < norm_score
    assert ddos_conf > norm_conf
    assert is_anomaly is True
    assert len(outliers) > 0
