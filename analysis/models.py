from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class CaptureReadiness(str, Enum):
    READY = "ready"
    DISABLED = "disabled"
    MISSING_SCAPY = "missing_scapy"
    NEEDS_ROOT = "needs_root"


@dataclass(frozen=True)
class CaptureStatus:
    readiness: CaptureReadiness
    running: bool
    interface: str | None = None
    message: str | None = None
    last_error: str | None = None


@dataclass(frozen=True)
class PacketEvent:
    """Normalized packet data used by analysis, storage, and detectors."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    size_bytes: int
    src_port: int | None = None
    dst_port: int | None = None

    @classmethod
    def now(
        cls,
        *,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        size_bytes: int,
        src_port: int | None = None,
        dst_port: int | None = None,
    ) -> "PacketEvent":
        return cls(
            timestamp=datetime.now(timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol.upper(),
            size_bytes=size_bytes,
            src_port=src_port,
            dst_port=dst_port,
        )


@dataclass(frozen=True)
class TrafficSnapshot:
    """Point-in-time summary of the rolling traffic window."""

    generated_at: datetime
    window_seconds: int
    total_packets: int
    packets_per_second: float
    unique_sources: int
    unique_destinations: int
    protocol_counts: dict[str, int]
    top_sources: list[tuple[str, int]]
