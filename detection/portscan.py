from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from secureops.detection.base import (
    DetectionAlert,
    make_alert,
)


class PortScanDetector:

    name = "portscan"

    PORT_THRESHOLD = 10
    TIME_WINDOW = 60

    def __init__(self):
        self.scan_data = defaultdict(list)
        self.alerted_ips = set()

    def evaluate_packet(
        self,
        event,
    ) -> list[DetectionAlert]:
    
        if event.protocol != "TCP":
            return []
            
        if event.dst_port is None:
            return []

        if event.src_port in (80, 443, 22):
            return []  
            
        current_time = event.timestamp

        self.scan_data[event.src_ip].append(
            (event.dst_port, current_time)
        )
        cutoff = current_time - timedelta(seconds=self.TIME_WINDOW)

        self.scan_data[event.src_ip] = [
            (port, ts)
            for port, ts in self.scan_data[event.src_ip]
            if ts >= cutoff
        ]
        self._cleanup(cutoff)

        unique_ports = {
            port
            for port, ts in self.scan_data[event.src_ip]
        }

        port_count = len(unique_ports)
        if (
            port_count >= self.PORT_THRESHOLD
            and event.src_ip not in self.alerted_ips
        ):
       
            self.alerted_ips.add(event.src_ip)

            return [
                make_alert(
                    detector=self.name,
                    severity="high",
                    reason="port-scan-detected",
                    observed_value=port_count,
                    threshold=self.PORT_THRESHOLD,
                    src_ip=event.src_ip,
                    confidence=90.0,
                    risk_score=85,
                    action="Logged",
                )
            ]

        return []
        
    def evaluate_snapshot(self, snapshot):
        return []

    def _cleanup(self, cutoff) -> None:
        stale = [
            src_ip
            for src_ip, events in self.scan_data.items()
            if not events or events[-1][1] < cutoff
        ]
        for src_ip in stale:
            self.scan_data.pop(src_ip, None)
            self.alerted_ips.discard(src_ip)
