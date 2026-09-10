"""
Unified Threat Detection Engine for NTRO Passive Unidirectional Monitoring.
Combines rule-based behavioral heuristics with Scikit-learn Isolation Forest ML anomaly scoring.
"""
from typing import List, Dict, Any, Optional, Tuple
from app.alerts.schema import ThreatAlert, ThreatClass, Severity
from app.alerts.store import AlertStore
from app.features.extractor import WindowFeatureExtractor
from app.models.anomaly_detector import MLAnomalyDetector
from app.detection.ddos import DDoSDetector
from app.detection.port_scan import PortScanDetector
from app.detection.beaconing import BeaconingDetector
from app.detection.dns_threats import DNSThreatDetector
from app.detection.encrypted_anomaly import EncryptedAnomalyDetector
from app.detection.exfiltration import ExfiltrationDetector


class ThreatDetectionEngine:
    """
    Central passive threat detection coordinator.
    Ingests unidirectional flow batches -> extracts features -> runs ML scoring -> evaluates 6 threat detectors.
    """
    def __init__(self, alert_store: Optional[AlertStore] = None):
        self.alert_store = alert_store or AlertStore()
        self.feature_extractor = WindowFeatureExtractor()
        self.ml_detector = MLAnomalyDetector()

        # Instantiate the six threat detection modules
        self.ddos_detector = DDoSDetector()
        self.port_scan_detector = PortScanDetector()
        self.beacon_detector = BeaconingDetector()
        self.dns_detector = DNSThreatDetector()
        self.encrypted_detector = EncryptedAnomalyDetector()
        self.exfil_detector = ExfiltrationDetector()

        # Cooldown tracker to prevent duplicate spamming within the same threat phase
        self._last_alert_time: Dict[str, float] = {}

    def process_window(self, flows: List[Dict[str, Any]], window_duration: float = 5.0) -> Dict[str, Any]:
        """
        Stream processing pipeline:
        1. Ingest window flows
        2. Extract 12-D window features
        3. Score ML Isolation Forest anomaly
        4. Evaluate 6 threat detection modules
        5. Store alerts and return analytical summary
        """
        # Step 1 & 2: Feature extraction
        features = self.feature_extractor.extract_features(flows, window_duration=window_duration)

        # Step 3: ML Anomaly detection
        is_ml_anomaly, raw_score, ml_conf, outlier_feats = self.ml_detector.score(features)

        new_alerts: List[ThreatAlert] = []

        # Step 4: Run the six threat modules
        detectors = [
            (ThreatClass.DDOS.value, self.ddos_detector),
            (ThreatClass.PORT_SCAN.value, self.port_scan_detector),
            (ThreatClass.C2_BEACON.value, self.beacon_detector),
            (ThreatClass.DGA_DNS.value, self.dns_detector),
            (ThreatClass.ENCRYPTED_ANOMALY.value, self.encrypted_detector),
            (ThreatClass.EXFILTRATION.value, self.exfil_detector),
        ]

        # Status tracking for 6 overview cards
        threat_status: Dict[str, str] = {tc.value: "NORMAL" for tc in ThreatClass}

        for threat_key, detector in detectors:
            alert = detector.detect(flows, features, ml_confidence=ml_conf if is_ml_anomaly else 0.0)
            if alert:
                threat_status[threat_key] = alert.severity
                new_alerts.append(alert)
                self.alert_store.add_alert(alert)

        # Return comprehensive streaming summary for dashboard
        return {
            "features": features,
            "is_anomaly": is_ml_anomaly,
            "ml_anomaly_score": raw_score,
            "ml_confidence": ml_conf,
            "outlier_features": outlier_feats,
            "new_alerts": new_alerts,
            "threat_status": threat_status,
            "flow_count": len(flows)
        }
