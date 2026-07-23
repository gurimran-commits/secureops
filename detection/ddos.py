from __future__ import annotations

import logging
from collections import deque
from datetime import timedelta

from secureops.analysis.models import PacketEvent, TrafficSnapshot
from secureops.detection.base import DetectionAlert, make_alert
from secureops.detection.classifier import AttackClassifier

logger = logging.getLogger(__name__)

class DDoSDetector:
    """Rule-based detector for volumetric and distributed flood patterns."""

    name = "ddos"

    def __init__(
        self,
        *,
        max_packets_per_second: float,
        max_unique_sources: int,
        protocol_flood_threshold: int,
        per_source_packet_threshold: int,
        per_source_window_seconds: int,
    ) -> None:
        self.max_packets_per_second = max_packets_per_second
        self.max_unique_sources = max_unique_sources
        self.protocol_flood_threshold = protocol_flood_threshold
        self.per_source_packet_threshold = per_source_packet_threshold
        self.per_source_window_seconds = per_source_window_seconds
        self._source_windows: dict[str, deque] = {}
        self._classifier = AttackClassifier()

    def evaluate_packet(self, event: PacketEvent) -> list[DetectionAlert]:
       
        window = self._source_windows.setdefault(event.src_ip, deque())
        window.append(event.timestamp)
        cutoff = event.timestamp - timedelta(seconds=self.per_source_window_seconds)
        while window and window[0] < cutoff:
            window.popleft()
        self._cleanup_sources(cutoff)

        if len(window) >= self.per_source_packet_threshold:

            ratio = len(window) / self.per_source_packet_threshold

            if ratio >= 5:
                severity = "critical"
                risk_score = 100
                confidence = 99.0

            elif ratio >= 3:
                severity = "high"
                risk_score = 80
                confidence = 90.0

            elif ratio >= 2:
                severity = "medium"
                risk_score = 60
                confidence = 75.0

            else:
                severity = "low"
                risk_score = 40
                confidence = 60.0

            return [
                make_alert(
                    detector=self.name,
                    severity=severity,
                    reason="single-source-packet-surge",
                    observed_value=len(window),
                    threshold=self.per_source_packet_threshold,
                    src_ip=event.src_ip,
                    confidence=confidence,
                    risk_score=risk_score,
                    action="Logged",
                )
            ]
        return []

    def evaluate_snapshot(self, snapshot: TrafficSnapshot) -> list[DetectionAlert]:  
        attack_type = self._classifier.classify(snapshot)
        top_ip = (
            snapshot.top_sources[0][0]
            if snapshot.top_sources
            else None
        )

        if attack_type:
            logger.info("attack classifier detected %s", attack_type)
        alerts: list[DetectionAlert] = []
        packet_rate_exceeded = (
            snapshot.packets_per_second >= self.max_packets_per_second
        )

        unique_sources_exceeded = (
            snapshot.unique_sources >= self.max_unique_sources
        )

        protocol_flood_detected = any(
            count >= self.protocol_flood_threshold
            for count in snapshot.protocol_counts.values()
        )
        conditions_met = sum([
            packet_rate_exceeded,
            unique_sources_exceeded,
            protocol_flood_detected,
        ])
        suspected_ddos = conditions_met >= 2
        if suspected_ddos and packet_rate_exceeded:

            ratio = (
                snapshot.packets_per_second
                / self.max_packets_per_second
            )

            if ratio >= 2:
                severity = "critical"
                risk_score = 100
                confidence = 99.0

            elif ratio >= 1.5:
                severity = "high"
                risk_score = 85
                confidence = 92.0

            elif ratio >= 1.0:
                severity = "medium"
                risk_score = 65
                confidence = 80.0

            else:
                severity = "low"
                risk_score = 45
                confidence = 65.0

            alerts.append(
                make_alert(
                    detector=self.name,
                    severity=severity,
                    reason="packet-rate-threshold",
                    observed_value=snapshot.packets_per_second,
                    threshold=self.max_packets_per_second,
                    src_ip=top_ip,
                    confidence=confidence,
                    risk_score=risk_score,
                    action="Logged",
                )
            )

        if suspected_ddos and unique_sources_exceeded:

            ratio = (
                snapshot.unique_sources
                / self.max_unique_sources
            )

            if ratio >= 2:
                severity = "critical"
                risk_score = 100
                confidence = 99.0

            elif ratio >=1.5 :
                severity = "high"
                risk_score = 85
                confidence = 92.0

            elif ratio >= 1:
                severity = "medium"
                risk_score = 65
                confidence = 80.0

            else:
                severity = "low"
                risk_score = 45
                confidence = 65.0

            alerts.append(
                make_alert(
                    detector=self.name,
                    severity=severity,
                    reason="unique-source-surge",
                    observed_value=snapshot.unique_sources,
                    threshold=self.max_unique_sources,
                    src_ip=top_ip,
                    confidence=confidence,
                    risk_score=risk_score,
                    action="Logged",
                )
            )

        for protocol, count in snapshot.protocol_counts.items():

            if suspected_ddos and count >= self.protocol_flood_threshold:

                ratio = count / self.protocol_flood_threshold

                if ratio >= 2:
                    severity = "critical"
                    risk_score = 100
                    confidence = 99.0

                elif ratio >= 1.5:
                    severity = "high"
                    risk_score = 85
                    confidence = 92.0

                elif ratio >= 1.0:
                    severity = "medium"
                    risk_score = 65
                    confidence = 80.0

                else:
                    severity = "low"
                    risk_score = 45
                    confidence = 65.0

                alerts.append(
                    make_alert(
                        detector=self.name,
                        severity=severity,
                        reason=f"{protocol.lower()}-flood-threshold",
                        observed_value=count,
                        threshold=self.protocol_flood_threshold,
                        src_ip=top_ip,
                        confidence=confidence,
                        risk_score=risk_score,
                        action="Logged",
                    )
                )

        return alerts

    def _cleanup_sources(self, cutoff) -> None:
        stale = [
            src_ip
            for src_ip, window in self._source_windows.items()
            if not window or window[-1] < cutoff
        ]
        for src_ip in stale:
            self._source_windows.pop(src_ip, None)
