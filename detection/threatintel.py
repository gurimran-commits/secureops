from collections import defaultdict
from datetime import datetime, timezone
from threading import RLock

from secureops.detection.geoip_lookup import lookup_ip
from secureops.threatfeeds.reputation import ThreatReputation


class ThreatIntel:

    def __init__(self):
        self.reputation = ThreatReputation()
        self._lock = RLock()
        self.attackers = defaultdict(
            lambda: {
                "first_seen": None,
                "last_seen": None,
                "attack_count": 0,
                "risk_score": 0,
                "attack_types": set(),
                "reputation": None,
                "confidence": 0,
                "country": None,
                "city": None,
                "isp": None,
            }
        )

    def record_attack(
        self,
        ip,
        attack_type,
        risk_score,
    ):

        if not ip or ip == "unknown":
            return

        with self._lock:
            attacker = self.attackers[ip]

            if attacker["country"] is None:

                geo = lookup_ip(ip)

                attacker["country"] = geo["country"]
                attacker["city"] = geo["city"]
                attacker["isp"] = geo["isp"]

            now = datetime.now(timezone.utc).isoformat()

            if attacker["first_seen"] is None:
                attacker["first_seen"] = now

            attacker["last_seen"] = now

            attacker["attack_count"] += 1

            attacker["risk_score"] = min(
                100,
                attacker["risk_score"] + risk_score
            )

            attacker["attack_types"].add(attack_type)
            rep = self.reputation.lookup(ip)

            attacker["reputation"] = rep["reputation"]
            attacker["confidence"] = rep["confidence"]
    def get_attackers(self):

        result = []

        with self._lock:
            items = list(self.attackers.items())

        for ip, data in items:

            result.append(
                {
                    "ip": ip,
                    "country": data["country"],
                    "city": data["city"],
                    "isp": data["isp"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "attack_count": data["attack_count"],
                    "risk_score": data["risk_score"],
                    "reputation": data["reputation"],
                    "confidence": data["confidence"],
                    "attack_types": list(
                        data["attack_types"]
                    ),
                }
            )

        return result
