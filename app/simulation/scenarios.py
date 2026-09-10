"""
Scenario Coordinator & Demo Sequence Controller for NTRO Threat Detection.
Manages the automated 6-phase demo loop, speed factors, and manual threat triggering.
"""
import time
from typing import List, Dict, Any, Tuple
from app.simulation.generator import TelemetryGenerator

class DemoScenarioCoordinator:
    """
    Coordinates real-time simulated telemetry windows for the SIH 2026 demo.
    Follows the exact 6-phase evaluation sequence with seamless looping.
    """
    PHASES = [
        ("PHASE 1: NORMAL TRAFFIC", 16.0, "NORMAL"),
        ("PHASE 2: PORT SCAN RECONNAISSANCE", 12.0, "PORT_SCAN"),
        ("PHASE 3: NORMAL TRAFFIC BASELINE", 10.0, "NORMAL"),
        ("PHASE 4: BOTNET C2 BEACONING", 14.0, "C2_BEACON"),
        ("PHASE 5: VOLUMETRIC DDoS SURGE", 14.0, "DDOS"),
        ("PHASE 6: NORMAL TRAFFIC RECOVERY", 10.0, "NORMAL"),
    ]

    def __init__(self, speed_multiplier: float = 1.0):
        self.generator = TelemetryGenerator()
        self.speed_multiplier = max(0.2, min(5.0, speed_multiplier))
        self.is_running = False
        self.is_paused = False
        self.current_phase_index = 0
        self.phase_elapsed_time = 0.0
        self.active_mode = "FULL_SEQUENCE"  # Or specific: "PORT_SCAN", "C2_BEACON", etc.
        self.last_tick_time = time.time()
        self.total_elapsed = 0.0

    def start(self, mode: str = "FULL_SEQUENCE") -> None:
        self.is_running = True
        self.is_paused = False
        self.active_mode = mode
        self.current_phase_index = 0
        self.phase_elapsed_time = 0.0
        self.last_tick_time = time.time()

    def pause(self) -> None:
        self.is_paused = True

    def resume(self) -> None:
        self.is_paused = False
        self.last_tick_time = time.time()

    def stop(self) -> None:
        self.is_running = False
        self.is_paused = False
        self.current_phase_index = 0
        self.phase_elapsed_time = 0.0

    def reset(self) -> None:
        self.stop()
        self.generator = TelemetryGenerator()
        self.total_elapsed = 0.0

    def set_speed(self, speed: float) -> None:
        self.speed_multiplier = max(0.2, min(5.0, speed))

    def step_window(self, dt: float = 1.0) -> Tuple[str, str, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Advance simulation clock by dt seconds and generate a batch of flows.
        Returns:
            (phase_name, threat_mode, flows, window_stats)
        """
        if not self.is_running:
            # Generate baseline background flows even when demo is idle
            flows = [self.generator.generate_normal_flow() for _ in range(12)]
            stats = self._calc_window_stats(flows, dt)
            return ("STANDBY: NORMAL TRAFFIC", "NORMAL", flows, stats)

        effective_dt = dt * self.speed_multiplier
        self.phase_elapsed_time += effective_dt
        self.total_elapsed += effective_dt

        if self.active_mode == "FULL_SEQUENCE":
            curr_name, max_dur, curr_threat = self.PHASES[self.current_phase_index]
            if self.phase_elapsed_time >= max_dur:
                # Transition to next phase in sequence
                self.phase_elapsed_time = 0.0
                self.current_phase_index = (self.current_phase_index + 1) % len(self.PHASES)
                curr_name, max_dur, curr_threat = self.PHASES[self.current_phase_index]
        else:
            curr_name = f"MANUAL TEST: {self.active_mode}"
            curr_threat = self.active_mode

        # Generate traffic according to active threat scenario
        flows = []
        # Always inject baseline background flows for realistic operational environment
        normal_count = 15 if curr_threat != "DDOS" else 5
        flows.extend([self.generator.generate_normal_flow() for _ in range(normal_count)])

        if curr_threat == "NORMAL":
            # Just background flows
            pass
        elif curr_threat == "PORT_SCAN":
            flows.extend(self.generator.generate_port_scan_flows(count=55))
        elif curr_threat == "C2_BEACON":
            flows.extend(self.generator.generate_c2_beacon_flows(count=20))
        elif curr_threat == "DDOS":
            flows.extend(self.generator.generate_ddos_flows(count=350))
        elif curr_threat == "DGA_DNS":
            flows.extend(self.generator.generate_dga_dns_flows(count=30))
        elif curr_threat == "ENCRYPTED_ANOMALY":
            flows.extend(self.generator.generate_encrypted_anomaly_flows(count=22))
        elif curr_threat == "EXFILTRATION":
            flows.extend(self.generator.generate_exfiltration_flows(count=16))

        stats = self._calc_window_stats(flows, dt)
        return (curr_name, curr_threat, flows, stats)

    def _calc_window_stats(self, flows: List[Dict[str, Any]], dt: float) -> Dict[str, Any]:
        """Compute aggregated window bandwidth, packet rate, and flow counts."""
        total_packets = sum(f.get("packets", 1) for f in flows)
        total_bytes = sum(f.get("bytes", 0) for f in flows)
        num_flows = len(flows)

        # Scale rates appropriately for dashboard representation
        if any(f.get("threat_label") == "DDOS" for f in flows):
            mbps = round(48.5 + (total_bytes % 120000) / 10000.0, 2)
            pkts_sec = 48500 + total_packets * 15
            flows_sec = 4200 + num_flows * 8
        elif any(f.get("threat_label") == "PORT_SCAN" for f in flows):
            mbps = round(7.8 + (total_bytes % 30000) / 10000.0, 2)
            pkts_sec = 3100 + total_packets * 8
            flows_sec = 1850 + num_flows * 10
        elif any(f.get("threat_label") == "EXFILTRATION" for f in flows):
            mbps = round(32.4 + (total_bytes % 50000) / 10000.0, 2)
            pkts_sec = 6800 + total_packets * 5
            flows_sec = 950 + num_flows * 4
        else:
            # Benign baseline: ~4.5 - 6.2 Mbps
            mbps = round(4.8 + ((total_bytes * 8) / 1_000_000.0) * 0.8, 2)
            pkts_sec = 1200 + total_packets * 6
            flows_sec = 420 + num_flows * 3

        return {
            "mbps": mbps,
            "packets_sec": pkts_sec,
            "flows_sec": flows_sec,
            "active_flows": 14000 + (flows_sec * 3),
            "flow_count": num_flows,
            "total_bytes": total_bytes,
        }
