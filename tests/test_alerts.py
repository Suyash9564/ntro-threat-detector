import pytest
from app.alerts.schema import ThreatAlert, ThreatClass, Severity
from app.alerts.store import AlertStore

def test_alert_schema():
    alert = ThreatAlert(
        threat_class=ThreatClass.PORT_SCAN.value,
        severity=Severity.HIGH.value,
        confidence=0.96,
        source_ip="10.0.4.21",
        destination="10.0.4.0/24",
        evidence={"unique_ports": 47, "unique_hosts": 13},
        detection_method=["fan_out", "ml"],
        why_flagged=["Observed 47 unique ports", "Connection rate exceeded baseline"]
    )
    d = alert.to_dict()
    assert d["flow_id"].startswith("FLW-")
    assert d["severity"] == "HIGH"
    assert d["confidence"] == 0.96
    assert len(d["why_flagged"]) == 2

    restored = ThreatAlert.from_dict(d)
    assert restored.flow_id == alert.flow_id
    assert restored.source_ip == "10.0.4.21"

def test_alert_store():
    store = AlertStore(max_alerts=10)
    for i in range(15):
        store.add_alert(ThreatAlert(
            threat_class=ThreatClass.DDOS.value if i % 2 == 0 else ThreatClass.C2_BEACON.value,
            severity=Severity.CRITICAL.value if i == 0 else Severity.HIGH.value,
            confidence=0.95,
            source_ip=f"10.0.0.{i}",
            destination="10.0.0.1",
            evidence={},
            detection_method=["rules"],
            why_flagged=["Test explanation"]
        ))

    assert store.total_count() == 10
    counts = store.get_counts_by_threat()
    assert counts[ThreatClass.DDOS.value] > 0
    assert store.get_critical_count() >= 0
