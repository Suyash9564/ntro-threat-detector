import pytest
import numpy as np
from app.simulation.generator import TelemetryGenerator
from app.features.extractor import WindowFeatureExtractor

def test_feature_extractor():
    gen = TelemetryGenerator()
    extractor = WindowFeatureExtractor()

    flows = [gen.generate_normal_flow() for _ in range(20)]
    feat_dict = extractor.extract_features(flows, window_duration=5.0)

    for name in extractor.FEATURE_NAMES:
        assert name in feat_dict

    assert feat_dict["packet_rate"] > 0
    assert feat_dict["unique_dst_hosts"] > 0

    vec = extractor.to_vector(feat_dict)
    assert isinstance(vec, np.ndarray)
    assert len(vec) == len(extractor.FEATURE_NAMES)
