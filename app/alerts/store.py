"""
Thread-safe in-memory Alert Store for real-time aggregation and filtering.
"""
import threading
from typing import List, Dict, Any, Optional
from app.alerts.schema import ThreatAlert, ThreatClass, Severity


class AlertStore:
    """Thread-safe storage and analytical aggregator for Threat Alerts."""
    def __init__(self, max_alerts: int = 500):
        self.max_alerts = max_alerts
        self._alerts: List[ThreatAlert] = []
        self._lock = threading.Lock()

    def add_alert(self, alert: ThreatAlert) -> None:
        with self._lock:
            # Insert at head (latest first)
            self._alerts.insert(0, alert)
            if len(self._alerts) > self.max_alerts:
                self._alerts.pop()

    def get_all(self, limit: Optional[int] = None) -> List[ThreatAlert]:
        with self._lock:
            if limit:
                return list(self._alerts[:limit])
            return list(self._alerts)

    def get_by_flow_id(self, flow_id: str) -> Optional[ThreatAlert]:
        with self._lock:
            for a in self._alerts:
                if a.flow_id == flow_id:
                    return a
        return None

    def get_counts_by_threat(self) -> Dict[str, int]:
        counts = {tc.value: 0 for tc in ThreatClass}
        with self._lock:
            for a in self._alerts:
                if a.threat_class in counts:
                    counts[a.threat_class] += 1
                else:
                    counts[a.threat_class] = 1
        return counts

    def get_counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        with self._lock:
            for a in self._alerts:
                if a.severity in counts:
                    counts[a.severity] += 1
                else:
                    counts[a.severity] = 1
        return counts

    def get_critical_count(self) -> int:
        with self._lock:
            return sum(1 for a in self._alerts if a.severity == Severity.CRITICAL.value)

    def total_count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()
