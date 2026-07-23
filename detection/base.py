from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from secureops.analysis.models import PacketEvent, TrafficSnapshot


@dataclass(frozen=True)
class DetectionAlert:
    detector: str
    timestamp: datetime
    severity: str
    reason: str
    observed_value: float | str
    threshold: float | str

    src_ip: str | None = None

    confidence: float = 0.0
    risk_score: int = 0
    action: str = "Logged"

class Detector(Protocol):
    name: str

    def evaluate_packet(self, event: PacketEvent) -> list[DetectionAlert]:
        ...

    def evaluate_snapshot(self, snapshot: TrafficSnapshot) -> list[DetectionAlert]:
        ...


def make_alert(
    *,
    detector: str,
    severity: str,
    reason: str,
    observed_value: float | str,
    threshold: float | str,
    src_ip: str | None = None,
    confidence: float = 0.0,
    risk_score: int = 0,
    action: str = "Logged",
) -> DetectionAlert:
    return DetectionAlert(
    detector=detector,
    timestamp=datetime.now(timezone.utc),
    severity=severity,
    reason=reason,
    observed_value=observed_value,
    threshold=threshold,
    src_ip=src_ip,
    confidence=confidence,
    risk_score=risk_score,
    action=action,
)
