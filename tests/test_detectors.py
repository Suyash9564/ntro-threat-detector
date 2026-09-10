import pytest
from app.simulation.generator import TelemetryGenerator
from app.features.extractor import WindowFeatureExtractor
from app.alerts.schema import ThreatClass
from app.detection.ddos import DDoSDetector
from app.detection.port_scan import PortScanDetector
from app.detection.beaconing import BeaconingDetector
from app.detection.dns_threats import DNSThreatDetector
from app.detection.encrypted_anomaly import EncryptedAnomalyDetector
from app.detection.exfiltration import ExfiltrationDetector
from app.detection.engine import ThreatDetectionEngine

def test_all_six_detectors():
    gen = TelemetryGenerator()
    extractor = WindowFeatureExtractor()

    # 1. DDoS Detector
    ddos_detector = DDoSDetector()
    ddos_flows = gen.generate_ddos_flows(count=150)
    feats = extractor.extract_features(ddos_flows, 5.0)
    alert = ddos_detector.detect(ddos_flows, feats, 0.9)
    assert alert is not None
    assert alert.threat_class == ThreatClass.DDOS.value
    assert alert.confidence >= 0.90
    assert len(alert.why_flagged) >= 4

    # 2. Port Scan Detector
    ps_detector = PortScanDetector()
    ps_flows = gen.generate_port_scan_flows(count=50)
    feats = extractor.extract_features(ps_flows, 5.0)
    alert = ps_detector.detect(ps_flows, feats, 0.9)
    assert alert is not None
    assert alert.threat_class == ThreatClass.PORT_SCAN.value
    assert alert.confidence >= 0.90
    assert alert.evidence["unique_destination_ports"] >= 25

    # 3. Beaconing Detector
    beacon_detector = BeaconingDetector()
    beacon_flows = gen.generate_c2_beacon_flows(count=20)
    feats = extractor.extract_features(beacon_flows, 5.0)
    alert = beacon_detector.detect(beacon_flows, feats, 0.9)
    assert alert is not None
    assert alert.threat_class == ThreatClass.C2_BEACON.value
    assert alert.confidence >= 0.90

    # 4. DNS Threat Detector
    dns_detector = DNSThreatDetector()
    dns_flows = gen.generate_dga_dns_flows(count=15)
    feats = extractor.extract_features(dns_flows, 5.0)
    alert = dns_detector.detect(dns_flows, feats, 0.9)
    assert alert is not None
    assert alert.threat_class == ThreatClass.DGA_DNS.value
    assert alert.confidence >= 0.90

    # 5. Encrypted Anomaly Detector (Metadata Only)
    enc_detector = EncryptedAnomalyDetector()
    enc_flows = gen.generate_encrypted_anomaly_flows(count=15)
    feats = extractor.extract_features(enc_flows, 5.0)
    alert = enc_detector.detect(enc_flows, feats, 0.9)
    assert alert is not None
    assert alert.threat_class == ThreatClass.ENCRYPTED_ANOMALY.value
    assert alert.evidence["payload_decryption_status"] == "STRICTLY DISABLED (Metadata-Only)"

    # 6. Exfiltration Detector
    exfil_detector = ExfiltrationDetector()
    exfil_flows = gen.generate_exfiltration_flows(count=10)
    feats = extractor.extract_features(exfil_flows, 5.0)
    alert = exfil_detector.detect(exfil_flows, feats, 0.9)
    assert alert is not None
    assert alert.threat_class == ThreatClass.EXFILTRATION.value
    assert alert.confidence >= 0.90

def test_engine_normal_traffic_no_spurious_critical_alerts():
    engine = ThreatDetectionEngine()
    gen = TelemetryGenerator()
    normal_flows = [gen.generate_normal_flow() for _ in range(25)]
    summary = engine.process_window(normal_flows, 5.0)
    assert len(summary["new_alerts"]) == 0
    assert all(status == "NORMAL" for status in summary["threat_status"].values())
