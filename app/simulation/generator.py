"""
Realistic Network Flow Telemetry Generator for NTRO Unidirectional Threat Detection.
Generates realistic baseline normal traffic and 6 distinct cyber threat attack profiles.
"""
import time
import math
import random
from typing import List, Dict, Any, Optional

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given domain string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


class TelemetryGenerator:
    """
    Generates realistic IP flow telemetry for passive sensor ingestion.
    Enforces passive observer characteristics:
    - Never initiates handshakes
    - Observes one-way traffic streams
    - Metadata-only extraction for encrypted traffic
    """
    def __init__(self, seed: Optional[int] = 42):
        if seed is not None:
            random.seed(seed)
        self.flow_counter = 0

    def _next_flow_id(self) -> str:
        self.flow_counter += 1
        return f"FLW-{self.flow_counter:07d}"

    def generate_normal_flow(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Generate a realistic benign flow record."""
        ts = timestamp or time.time()
        protocols = ["TCP", "TCP", "TCP", "UDP", "UDP", "TLS"]
        proto = random.choice(protocols)

        src_ip = f"10.0.{random.randint(1, 10)}.{random.randint(10, 250)}"
        dst_servers = [
            "142.250.190.46",  # Google
            "151.101.65.140",   # Fastly CDN
            "104.244.42.1",     # Cloudflare
            "13.107.42.14",     # Microsoft
            "8.8.8.8",          # Public DNS
            "1.1.1.1",          # Cloudflare DNS
        ]
        dst_ip = random.choice(dst_servers)

        if proto == "UDP" and dst_ip in ["8.8.8.8", "1.1.1.1"]:
            dst_port = 53
            packets = random.randint(2, 4)
            bytes_out = random.randint(70, 150)
            bytes_in = random.randint(150, 400)
            tcp_flags = ""
            domain = random.choice(["api.github.com", "update.microsoft.com", "cdn.cloudflare.net", "ntro.gov.in", "aws.amazon.com"])
            domain_entropy = calculate_shannon_entropy(domain)
            record_type = "A"
        elif proto == "TLS":
            dst_port = 443
            packets = random.randint(15, 60)
            bytes_out = random.randint(1200, 5000)
            bytes_in = random.randint(5000, 45000)
            tcp_flags = "ACK,PSH"
            domain = "secure.enterprise.org"
            domain_entropy = 2.4
            record_type = "NONE"
        else:
            dst_port = random.choice([80, 443, 8080, 22])
            packets = random.randint(8, 45)
            bytes_out = random.randint(800, 3500)
            bytes_in = random.randint(2000, 30000)
            tcp_flags = "ACK,SYN" if random.random() < 0.15 else "ACK"
            domain = ""
            domain_entropy = 0.0
            record_type = "NONE"

        total_bytes = bytes_out + bytes_in
        duration = round(random.uniform(0.1, 4.5), 3)
        pkt_rate = round(packets / max(0.05, duration), 1)
        byte_rate = round(total_bytes / max(0.05, duration), 1)
        out_in_ratio = round(bytes_out / max(1, bytes_in), 3)

        return {
            "timestamp": ts,
            "flow_id": self._next_flow_id(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": dst_port,
            "protocol": proto,
            "packets": packets,
            "bytes": total_bytes,
            "duration": duration,
            "tcp_flags": tcp_flags,
            "packet_rate": pkt_rate,
            "byte_rate": byte_rate,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "out_in_ratio": out_in_ratio,
            "domain": domain,
            "domain_length": len(domain),
            "entropy": round(domain_entropy, 3),
            "query_frequency": round(random.uniform(0.2, 1.8), 2),
            "record_type": record_type,
            "inter_arrival_time": round(random.uniform(1.5, 9.0), 3),
            "periodicity_score": round(random.uniform(0.05, 0.25), 3),
            "destination_repetition": random.randint(1, 2),
            "tls_fingerprint": "c02f,c030,cca8" if proto == "TLS" else "",
            "packet_size_variance": round(random.uniform(150.0, 350.0), 1),
            "timing_variance": round(random.uniform(0.35, 1.2), 3),
            "threat_label": "NORMAL"
        }

    def generate_port_scan_flows(self, count: int = 50, timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """Simulate reconnaissance: a single host rapidly probing multiple ports/hosts."""
        ts = timestamp or time.time()
        scanner_ip = "10.0.4.21"
        target_subnet = "10.0.4."
        flows = []

        # Generate probes across 45+ unique ports and 12+ unique hosts
        target_hosts = [f"{target_subnet}{h}" for h in range(10, 25)]
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017]
        additional_ports = list(range(1000, 1050))
        scan_ports = common_ports + additional_ports

        for i in range(count):
            dport = scan_ports[i % len(scan_ports)]
            dhost = random.choice(target_hosts)
            flows.append({
                "timestamp": ts + (i * 0.04),
                "flow_id": self._next_flow_id(),
                "src_ip": scanner_ip,
                "dst_ip": dhost,
                "src_port": 50000 + i,
                "dst_port": dport,
                "protocol": "TCP",
                "packets": 1,
                "bytes": 60,
                "duration": 0.02,
                "tcp_flags": "SYN",
                "packet_rate": 50.0,
                "byte_rate": 3000.0,
                "bytes_out": 60,
                "bytes_in": 0,
                "out_in_ratio": 60.0,
                "domain": "",
                "domain_length": 0,
                "entropy": 0.0,
                "query_frequency": 0.0,
                "record_type": "NONE",
                "inter_arrival_time": 0.04,
                "periodicity_score": 0.1,
                "destination_repetition": 1,
                "tls_fingerprint": "",
                "packet_size_variance": 0.0,
                "timing_variance": 0.005,
                "threat_label": "PORT_SCAN"
            })
        return flows

    def generate_c2_beacon_flows(self, count: int = 25, timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """Simulate Botnet C2 beaconing: regular inter-arrival times, low jitter, small destination set."""
        ts = timestamp or time.time()
        infected_host = "10.0.2.88"
        c2_ip = "185.220.101.5"  # External adversary C2 node
        flows = []
        nominal_interval = 5.0  # Exactly 5-second beacon cycle

        for i in range(count):
            jitter = random.uniform(-0.04, 0.04)  # Extremely low jitter (<0.05s)
            iat = round(nominal_interval + jitter, 3)
            flows.append({
                "timestamp": ts + (i * nominal_interval) + jitter,
                "flow_id": self._next_flow_id(),
                "src_ip": infected_host,
                "dst_ip": c2_ip,
                "src_port": 49820 + (i % 3),
                "dst_port": 443,
                "protocol": "TLS",
                "packets": 12,
                "bytes": 1420,
                "duration": 0.42,
                "tcp_flags": "ACK,PSH",
                "packet_rate": 28.5,
                "byte_rate": 3380.0,
                "bytes_out": 820,
                "bytes_in": 600,
                "out_in_ratio": 1.36,
                "domain": "sync-time-api.org",
                "domain_length": 17,
                "entropy": 2.82,
                "query_frequency": 0.2,
                "record_type": "A",
                "inter_arrival_time": iat,
                "periodicity_score": 0.96,  # Very high periodicity
                "destination_repetition": 18 + i,  # Highly repeated destination
                "tls_fingerprint": "c02f,c030,009e,009c",
                "packet_size_variance": 12.0,  # Fixed size heartbeat
                "timing_variance": 0.02,  # Ultra-low timing variance
                "threat_label": "C2_BEACON"
            })
        return flows

    def generate_ddos_flows(self, count: int = 300, timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """Simulate Volumetric / Protocol DDoS: SYN flood surge to 40-60 Mbps, high source dispersion."""
        ts = timestamp or time.time()
        target_server = "10.0.0.5"
        target_port = 443
        flows = []

        for i in range(count):
            # Highly diverse spoofed source IPs
            spoofed_src = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            sport = random.randint(1024, 65535)
            # High packet rate per flow
            packets = random.randint(150, 450)
            bytes_val = packets * random.randint(600, 1400)
            flows.append({
                "timestamp": ts + (i * 0.002),
                "flow_id": self._next_flow_id(),
                "src_ip": spoofed_src,
                "dst_ip": target_server,
                "src_port": sport,
                "dst_port": target_port,
                "protocol": "TCP",
                "packets": packets,
                "bytes": bytes_val,
                "duration": 0.08,
                "tcp_flags": "SYN",
                "packet_rate": round(packets / 0.08, 1),
                "byte_rate": round(bytes_val / 0.08, 1),
                "bytes_out": bytes_val,
                "bytes_in": 0,
                "out_in_ratio": 100.0,
                "domain": "",
                "domain_length": 0,
                "entropy": 0.0,
                "query_frequency": 0.0,
                "record_type": "NONE",
                "inter_arrival_time": 0.002,
                "periodicity_score": 0.05,
                "destination_repetition": count,
                "tls_fingerprint": "",
                "packet_size_variance": 15.0,
                "timing_variance": 0.001,
                "threat_label": "DDOS"
            })
        return flows

    def generate_dga_dns_flows(self, count: int = 35, timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """Simulate DGA domains and DNS tunnelling: high entropy strings, TXT records, abnormal query length."""
        ts = timestamp or time.time()
        infected_host = "10.0.5.114"
        dns_resolver = "10.0.0.2"
        flows = []

        dga_samples = [
            "xqj9k28bfmwz91lpa0c.threatcorp.biz",
            "vzkq92mpxlae0817ghz.cdn-cache01.info",
            "qw987zxmcbvnlasdfk1290.tunnel.dynamic-dns.net",
            "a89f7b1c3e0d29485bb7a19.exfil-data.top",
            "pxzlkjqwmvnbrty891230491823.exfil.org",
            "99018230918230918230918230.tunnel.cc"
        ]

        for i in range(count):
            domain = dga_samples[i % len(dga_samples)]
            entropy = calculate_shannon_entropy(domain.split('.')[0])
            record_type = "TXT" if i % 2 == 0 else "NULL"
            flows.append({
                "timestamp": ts + (i * 0.1),
                "flow_id": self._next_flow_id(),
                "src_ip": infected_host,
                "dst_ip": dns_resolver,
                "src_port": 53000 + i,
                "dst_port": 53,
                "protocol": "UDP",
                "packets": 2,
                "bytes": 512 + (len(domain) * 4),
                "duration": 0.03,
                "tcp_flags": "",
                "packet_rate": 66.0,
                "byte_rate": 20000.0,
                "bytes_out": 400 + len(domain),
                "bytes_in": 150,
                "out_in_ratio": 3.2,
                "domain": domain,
                "domain_length": len(domain),
                "entropy": round(entropy, 3),
                "query_frequency": 14.5,  # Unusually frequent DNS queries
                "record_type": record_type,
                "inter_arrival_time": 0.1,
                "periodicity_score": 0.4,
                "destination_repetition": 12,
                "tls_fingerprint": "",
                "packet_size_variance": 80.0,
                "timing_variance": 0.05,
                "threat_label": "DGA_DNS"
            })
        return flows

    def generate_encrypted_anomaly_flows(self, count: int = 20, timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Simulate Malware inside encrypted sessions (Metadata Only - ZERO Payload Decryption).
        Abnormal packet size distributions, burst timing anomalies, non-standard cipher profiles.
        """
        ts = timestamp or time.time()
        host_ip = "10.0.7.62"
        ext_target = "194.26.29.11"
        flows = []

        for i in range(count):
            flows.append({
                "timestamp": ts + (i * 0.25),
                "flow_id": self._next_flow_id(),
                "src_ip": host_ip,
                "dst_ip": ext_target,
                "src_port": 58200 + i,
                "dst_port": 8443,
                "protocol": "TLS",
                "packets": 85,
                "bytes": 48200,
                "duration": 1.2,
                "tcp_flags": "ACK,PSH",
                "packet_rate": 70.8,
                "byte_rate": 40166.0,
                "bytes_out": 38000,
                "bytes_in": 10200,
                "out_in_ratio": 3.72,
                "domain": "cloud-telemetry-backup.net",
                "domain_length": 26,
                "entropy": 3.1,
                "query_frequency": 1.0,
                "record_type": "NONE",
                "inter_arrival_time": 0.25,
                "periodicity_score": 0.72,
                "destination_repetition": 8,
                "tls_fingerprint": "771,4865-4866-4867,0-23-65281,29-23-24,0",  # Custom suspicious fingerprint
                "packet_size_variance": 890.5,  # Extreme packet size variance
                "timing_variance": 3.85,        # Burst timing anomaly
                "threat_label": "ENCRYPTED_ANOMALY"
            })
        return flows

    def generate_exfiltration_flows(self, count: int = 15, timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """Simulate Data Exfiltration: abnormal outbound byte volume, extreme out/in ratio, rare external target."""
        ts = timestamp or time.time()
        host_ip = "10.0.3.45"
        exfil_target = "198.51.100.77"  # Rare unclassified external server
        flows = []

        for i in range(count):
            bytes_out = random.randint(850000, 1850000)  # Multi-megabyte chunk
            bytes_in = random.randint(1200, 4500)       # Tiny ACKs
            duration = round(random.uniform(2.5, 4.0), 2)
            flows.append({
                "timestamp": ts + (i * 0.4),
                "flow_id": self._next_flow_id(),
                "src_ip": host_ip,
                "dst_ip": exfil_target,
                "src_port": 54310 + i,
                "dst_port": 443,
                "protocol": "TCP",
                "packets": random.randint(600, 1200),
                "bytes": bytes_out + bytes_in,
                "duration": duration,
                "tcp_flags": "ACK,PSH",
                "packet_rate": round(1000 / duration, 1),
                "byte_rate": round(bytes_out / duration, 1),
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "out_in_ratio": round(bytes_out / max(1, bytes_in), 2),  # ~200:1 to 1000:1 ratio
                "domain": "",
                "domain_length": 0,
                "entropy": 0.0,
                "query_frequency": 0.0,
                "record_type": "NONE",
                "inter_arrival_time": 0.4,
                "periodicity_score": 0.3,
                "destination_repetition": 15,
                "tls_fingerprint": "",
                "packet_size_variance": 450.0,
                "timing_variance": 0.12,
                "threat_label": "EXFILTRATION"
            })
        return flows
