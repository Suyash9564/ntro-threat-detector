"""
Feature Extraction and Engineering for Unidirectional Network Telemetry.
Aggregates packet and flow telemetry into rich behavioral feature vectors.
"""
import numpy as np
from typing import List, Dict, Any, Tuple
import math


class WindowFeatureExtractor:
    """
    Extracts statistical, timing, and behavioral features across sliding time windows.
    Strictly observes one-way IP telemetry without payload decryption.
    """
    FEATURE_NAMES = [
        "packet_rate",
        "byte_rate",
        "syn_ratio",
        "unique_dst_ports",
        "unique_dst_hosts",
        "fan_out_ratio",
        "iat_variance",
        "periodicity_score",
        "dns_entropy_max",
        "packet_size_variance",
        "out_in_ratio",
        "connection_rate"
    ]

    def extract_features(self, flows: List[Dict[str, Any]], window_duration: float = 5.0) -> Dict[str, Any]:
        """Compute aggregated window statistics and per-feature values."""
        if not flows:
            return {name: 0.0 for name in self.FEATURE_NAMES}

        duration = max(0.1, window_duration)
        total_packets = sum(f.get("packets", 1) for f in flows)
        total_bytes = sum(f.get("bytes", 0) for f in flows)
        bytes_out = sum(f.get("bytes_out", 0) for f in flows)
        bytes_in = sum(f.get("bytes_in", 0) for f in flows)

        packet_rate = float(total_packets) / duration
        byte_rate = float(total_bytes) / duration
        connection_rate = float(len(flows)) / duration

        # TCP Flag analysis
        syn_count = sum(1 for f in flows if "SYN" in f.get("tcp_flags", ""))
        syn_ratio = float(syn_count) / max(1, len(flows))

        # Host and Port dispersion (Fan-out)
        dst_ports = {f.get("dst_port") for f in flows if f.get("dst_port")}
        dst_hosts = {f.get("dst_ip") for f in flows if f.get("dst_ip")}
        src_hosts = {f.get("src_ip") for f in flows if f.get("src_ip")}

        unique_dst_ports = len(dst_ports)
        unique_dst_hosts = len(dst_hosts)
        unique_src_hosts = len(src_hosts)
        fan_out_ratio = float(unique_dst_ports) / max(1.0, float(unique_dst_hosts))

        # Inter-arrival time and periodicity metrics
        iats = [f.get("inter_arrival_time", 1.0) for f in flows if "inter_arrival_time" in f]
        iat_variance = float(np.var(iats)) if len(iats) > 1 else 0.5

        periodicity_scores = [f.get("periodicity_score", 0.0) for f in flows if "periodicity_score" in f]
        avg_periodicity = float(np.mean(periodicity_scores)) if periodicity_scores else 0.1

        # DNS Entropy & domain analysis
        entropies = [f.get("entropy", 0.0) for f in flows if f.get("entropy", 0.0) > 0.0]
        dns_entropy_max = float(max(entropies)) if entropies else 0.0

        # Encrypted session metadata variance
        pkt_size_vars = [f.get("packet_size_variance", 0.0) for f in flows if "packet_size_variance" in f]
        avg_pkt_size_var = float(np.mean(pkt_size_vars)) if pkt_size_vars else 100.0

        # Outbound vs Inbound byte ratio
        out_in_ratio = float(bytes_out) / max(1.0, float(bytes_in))

        return {
            "packet_rate": round(packet_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "syn_ratio": round(syn_ratio, 4),
            "unique_dst_ports": unique_dst_ports,
            "unique_dst_hosts": unique_dst_hosts,
            "unique_src_hosts": unique_src_hosts,
            "fan_out_ratio": round(fan_out_ratio, 2),
            "iat_variance": round(iat_variance, 4),
            "periodicity_score": round(avg_periodicity, 3),
            "dns_entropy_max": round(dns_entropy_max, 3),
            "packet_size_variance": round(avg_pkt_size_var, 2),
            "out_in_ratio": round(out_in_ratio, 2),
            "connection_rate": round(connection_rate, 2),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "flow_count": len(flows)
        }

    def to_vector(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        """Convert extracted dictionary to 1D numerical NumPy vector for ML."""
        return np.array([feature_dict.get(name, 0.0) for name in self.FEATURE_NAMES], dtype=float)
