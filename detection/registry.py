from __future__ import annotations

import logging

from secureops.analysis.models import PacketEvent, TrafficSnapshot
from secureops.detection.base import DetectionAlert, Detector
from secureops.response.firewall import block_ip

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Runs packet-level and snapshot-level checks across detector modules."""

    def __init__(self, detectors: list[Detector]) -> None:
        self.detectors = detectors

    def evaluate_packet(self, event: PacketEvent) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []

        for detector in self.detectors:
            try:
                detector_alerts = detector.evaluate_packet(event)
            except Exception:
                logger.exception("detector %s failed while evaluating packet", detector.name)
                continue

            for alert in detector_alerts:

                if (
                    alert.src_ip
                    and alert.severity in ["high", "critical"]
                ):
                    logger.info(
                        "requesting firewall block detector=%s ip=%s severity=%s",
                        alert.detector,
                        alert.src_ip,
                        alert.severity,
                    )

                    block_ip(alert.src_ip)

            alerts.extend(detector_alerts)

        return alerts

    def evaluate_snapshot(
        self,
        snapshot: TrafficSnapshot,
    ) -> list[DetectionAlert]:

        alerts: list[DetectionAlert] = []

        for detector in self.detectors:

            try:
                detector_alerts = detector.evaluate_snapshot(snapshot)
            except Exception:
                logger.exception("detector %s failed while evaluating snapshot", detector.name)
                continue

            for alert in detector_alerts:

                if (
                    alert.src_ip
                    and alert.severity in ["high", "critical"]
                ):
                    block_ip(alert.src_ip)

            alerts.extend(detector_alerts)

        return alerts
