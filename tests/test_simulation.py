import pytest
from app.simulation.generator import TelemetryGenerator, calculate_shannon_entropy
from app.simulation.scenarios import DemoScenarioCoordinator

def test_shannon_entropy():
    # Normal words have low/moderate entropy
    assert calculate_shannon_entropy("google") < 2.5
    # High randomness / long DGA string has high entropy
    assert calculate_shannon_entropy("xqj9k28bfmwz91lpa0c") > 3.8
    assert calculate_shannon_entropy("") == 0.0

def test_telemetry_normal_flow():
    gen = TelemetryGenerator()
    flow = gen.generate_normal_flow()
    assert "timestamp" in flow
    assert "flow_id" in flow
    assert "src_ip" in flow
    assert "dst_ip" in flow
    assert flow["threat_label"] == "NORMAL"

def test_telemetry_threat_flows():
    gen = TelemetryGenerator()
    port_scan = gen.generate_port_scan_flows(count=40)
    assert len(port_scan) == 40
    assert len({f["dst_port"] for f in port_scan}) >= 25

    beacon = gen.generate_c2_beacon_flows(count=15)
    assert len(beacon) == 15
    assert beacon[0]["periodicity_score"] >= 0.90

    ddos = gen.generate_ddos_flows(count=100)
    assert len(ddos) == 100
    assert ddos[0]["threat_label"] == "DDOS"

    dga = gen.generate_dga_dns_flows(count=10)
    assert len(dga) == 10
    assert dga[0]["entropy"] >= 3.6

    encrypted = gen.generate_encrypted_anomaly_flows(count=10)
    assert len(encrypted) == 10
    assert encrypted[0]["packet_size_variance"] >= 500.0

    exfil = gen.generate_exfiltration_flows(count=10)
    assert len(exfil) == 10
    assert exfil[0]["out_in_ratio"] >= 10.0

def test_scenario_coordinator_phases():
    coord = DemoScenarioCoordinator(speed_multiplier=2.0)
    coord.start("FULL_SEQUENCE")
    assert coord.is_running is True
    phase_name, threat_mode, flows, stats = coord.step_window(dt=1.0)
    assert "PHASE 1" in phase_name
    assert threat_mode == "NORMAL"
    assert len(flows) > 0
    assert stats["mbps"] > 0
