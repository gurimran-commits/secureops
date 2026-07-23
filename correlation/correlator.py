from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import RLock


class AttackCorrelator:

    def __init__(self):

        self.attack_history = defaultdict(list)
        self._lock = RLock()
        self.window = timedelta(hours=24)

    def add_attack(
        self,
        ip,
        attack_type,
    ):

        now = datetime.now(timezone.utc)
        with self._lock:
            self.attack_history[ip].append(
                {
                    "attack_type": attack_type,
                    "timestamp": now,
                }
            )
            self._cleanup(now)

    def get_campaigns(self):

        campaigns = []

        with self._lock:
            items = list(self.attack_history.items())

        for ip, events in items:

            attack_types = []

            for event in events:

                attack_type = event["attack_type"]

                if attack_type not in attack_types:
                    attack_types.append(
                        attack_type
                    )

            if len(attack_types) == 1:

                campaigns.append(
                    {
                        "ip": ip,
                        "campaign_type": attack_types[0].upper(),
                        "attack_chain": attack_types,
                        "attack_count": len(events),
                        "risk_score": self._risk_score(
                        attack_types
                        ),
                    }
                )
             
                continue

            campaign_type = (
                self._classify_campaign(
                    attack_types
                )
            )

            campaigns.append(
                {
                    "ip": ip,
                    "campaign_type":
                        campaign_type,
                    "attack_chain":
                        attack_types,
                    "attack_count":
                        len(events),
                    "risk_score":
                        self._risk_score(
                            attack_types
                        ),
                }
            )

        return campaigns
    def _classify_campaign(
        self,
        attack_types,
    ):

        attacks = set(
            attack_types
        )

        if (
            "portscan" in attacks
            and "bruteforce" in attacks 
            and "ddos" in attacks
        ):
            return "Full kill Chain"
              
        if (
            "portscan" in attacks
            and "bruteforce" in attacks
        ):
            return (
                "Reconnaissance + Credential Attack"
            )

        if "portscan" in attacks and "ddos" in attacks:
            return "Reconnaissance + DDoS"

        if len(attacks) > 1:
            return "Multi-Stage Attack"

        return "Unknown"
            
    def _risk_score(
        self,
        attack_types,
    ):

        score = 50

        score += (
            len(attack_types) * 15
        )

        if "ddos" in attack_types:
            score += 15

        if "bruteforce" in attack_types:
            score += 10

        return min(score, 100)

    def _cleanup(self, now):
        cutoff = now - self.window
        for ip in list(self.attack_history.keys()):
            self.attack_history[ip] = [
                event
                for event in self.attack_history[ip]
                if event["timestamp"] >= cutoff
            ]
            if not self.attack_history[ip]:
                self.attack_history.pop(ip, None)
