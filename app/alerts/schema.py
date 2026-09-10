"""
Standardized Threat Alert Schema for NTRO SIH 2026 Unidirectional Threat Detection.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional


class ThreatClass(str, Enum):
    DDOS = "DDOS"
    PORT_SCAN = "PORT_SCAN"
    C2_BEACON = "C2_BEACON"
    DGA_DNS = "DGA_DNS"
    ENCRYPTED_ANOMALY = "ENCRYPTED_ANOMALY"
    EXFILTRATION = "EXFILTRATION"

    @classmethod
    def display_name(cls, val: str) -> str:
        names = {
            cls.DDOS: "Volumetric / Protocol DDoS",
            cls.PORT_SCAN: "Reconnaissance / Port Scan",
            cls.C2_BEACON: "Botnet C2 Beaconing",
            cls.DGA_DNS: "DGA Domain / DNS Tunnelling",
            cls.ENCRYPTED_ANOMALY: "Encrypted Session Anomaly (Metadata Only)",
            cls.EXFILTRATION: "Data Exfiltration",
        }
        return names.get(val, val)


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatAlert:
    """
    Standardized alert payload representing an actionable detection event.
    Strictly passive ingest provenance: No active mitigation or payload decryption.
    """
    threat_class: str
    severity: str
    confidence: float
    source_ip: str
    destination: str
    evidence: Dict[str, Any]
    detection_method: List[str]
    why_flagged: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    flow_id: str = ""
    baseline_comparison: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.flow_id:
            self.flow_id = f"FLW-{abs(hash(f'{self.timestamp}-{self.threat_class}-{self.source_ip}')) % 1000000:06d}"
        # Bound confidence between 0.0 and 1.0
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatAlert":
        return cls(**data)
