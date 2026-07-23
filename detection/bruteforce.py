from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from secureops.detection.base import (
    DetectionAlert,
    make_alert,
)


class BruteForceDetector:

    name = "bruteforce"

    LOGIN_THRESHOLD = 20
    TIME_WINDOW = 60

    def __init__(self):
        self.attempts = defaultdict(list)
        self.alerted_ips = set()

    def evaluate_packet(self, event):

        if event.protocol != "TCP":
            return []

        if event.dst_port not in [22, 21, 23, 25, 110, 143, 3389]:
            return []

        current_time = event.timestamp

        self.attempts[event.src_ip].append(current_time)
        cutoff = current_time - timedelta(seconds=self.TIME_WINDOW)

        self.attempts[event.src_ip] = [
            ts
            for ts in self.attempts[event.src_ip]
            if ts >= cutoff
        ]
        self._cleanup(cutoff)

        count = len(self.attempts[event.src_ip])

        if (
            count >= self.LOGIN_THRESHOLD
            and event.src_ip not in self.alerted_ips
        ):
            self.alerted_ips.add(event.src_ip) 
            return [
                make_alert(
                    detector=self.name,
                    severity="high",
                    reason="brute-force-attempt",
                    observed_value=count,
                    threshold=self.LOGIN_THRESHOLD,
                    src_ip=event.src_ip,
                    confidence=88.0,
                    risk_score=80,
                    action="Logged",
                )
            ]

        return []

    def evaluate_snapshot(self, snapshot):
        return []

    def _cleanup(self, cutoff) -> None:
        stale = [
            src_ip
            for src_ip, attempts in self.attempts.items()
            if not attempts or attempts[-1] < cutoff
        ]
        for src_ip in stale:
            self.attempts.pop(src_ip, None)
            self.alerted_ips.discard(src_ip)
