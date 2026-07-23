from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class AttackClassifier:

    def classify(self, snapshot):

        protocols = snapshot.protocol_counts

        tcp = protocols.get("TCP", 0)
        udp = protocols.get("UDP", 0)
        icmp = protocols.get("ICMP", 0)

        logger.debug("traffic classifier counts tcp=%s udp=%s icmp=%s", tcp, udp, icmp)

        total = tcp + udp + icmp

        if total == 0:
            return None

        if tcp >= 500 and tcp > (udp + icmp):
            return "SYN Flood"

        if udp >= 500 and udp > (tcp + icmp):
            return "UDP Flood"

        if icmp >= 500 and icmp > (tcp + udp):
            return "ICMP Flood"

        return None
