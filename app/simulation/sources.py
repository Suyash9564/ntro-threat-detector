"""
Traffic Source Abstraction for NTRO Threat Detection.
Provides a clean interface for streaming telemetry from simulation, replay, or PCAPs.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Generator, Optional
import os


class TrafficSource(ABC):
    """Abstract interface for passive IP traffic ingestion."""

    @abstractmethod
    def read_window(self, window_size_seconds: float = 5.0) -> List[Dict[str, Any]]:
        """Read or generate a time window of raw flow/packet telemetry."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the traffic source state."""
        pass


class PCAPTrafficSource(TrafficSource):
    """
    Passive PCAP file replayer extracting flow metadata.
    Strictly read-only: parses headers, never decrypts payloads or transmits packets.
    """
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self._packets_read = 0

    def read_window(self, window_size_seconds: float = 5.0) -> List[Dict[str, Any]]:
        if not os.path.exists(self.pcap_path):
            return []
        flows = []
        try:
            from scapy.utils import PcapReader
            from scapy.layers.inet import IP, TCP, UDP
            import time

            count = 0
            # Read a batch of packets from PCAP and aggregate into lightweight flow records
            with PcapReader(self.pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    if count >= 200:
                        break
                    if IP in pkt:
                        ip_layer = pkt[IP]
                        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
                        sport = pkt[sport] if hasattr(pkt, 'sport') else 0
                        dport = pkt[dport] if hasattr(pkt, 'dport') else 0
                        pkt_len = len(pkt)
                        flows.append({
                            "timestamp": time.time(),
                            "flow_id": f"pcap-{count}",
                            "src_ip": ip_layer.src,
                            "dst_ip": ip_layer.dst,
                            "src_port": sport,
                            "dst_port": dport,
                            "protocol": proto,
                            "packets": 1,
                            "bytes": pkt_len,
                            "duration": 0.01,
                            "tcp_flags": "ACK" if TCP in pkt else "",
                            "packet_rate": 10.0,
                            "byte_rate": float(pkt_len) * 10.0,
                            "bytes_out": pkt_len,
                            "bytes_in": 0,
                            "out_in_ratio": 1.0,
                        })
                        count += 1
            return flows
        except Exception:
            return []

    def reset(self) -> None:
        self._packets_read = 0
