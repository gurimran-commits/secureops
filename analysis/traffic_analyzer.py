from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from threading import RLock

from secureops.analysis.models import PacketEvent, TrafficSnapshot


class TrafficAnalyzer:
    """Maintains a rolling packet window and exposes aggregate metrics."""

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._events: deque[PacketEvent] = deque()
        self._lock = RLock()

    def record(self, event: PacketEvent) -> TrafficSnapshot:
        with self._lock:
            self._events.append(event)
            self._trim(event.timestamp)
            return self._build_snapshot()

    def snapshot(self) -> TrafficSnapshot:
        with self._lock:
            self._trim(datetime.now(timezone.utc))
            return self._build_snapshot()

    def _build_snapshot(self) -> TrafficSnapshot:
        events = list(self._events)
        protocol_counts = Counter(event.protocol for event in events)
        source_counts = Counter(event.src_ip for event in events)
        destinations = {event.dst_ip for event in events}
        packets_per_second = len(events) / self.window_seconds if self.window_seconds else 0.0

        return TrafficSnapshot(
            generated_at=datetime.now(timezone.utc),
            window_seconds=self.window_seconds,
            total_packets=len(events),
            packets_per_second=round(packets_per_second, 2),
            unique_sources=len(source_counts),
            unique_destinations=len(destinations),
            protocol_counts=dict(protocol_counts),
            top_sources=source_counts.most_common(10),
        )

    def _trim(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()
