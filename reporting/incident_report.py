from datetime import datetime, timezone


class IncidentReportGenerator:

    def generate(self, attacker):

        attack_types = ", ".join(
            attacker["attack_types"]
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "attacker_ip": attacker["ip"],
            "country": attacker["country"],
            "city": attacker["city"],
            "isp": attacker["isp"],
            "reputation": attacker["reputation"],
            "confidence": attacker["confidence"],
            "attack_count": attacker["attack_count"],
            "risk_score": attacker["risk_score"],
            "attack_types": attack_types,
            "recommended_action": self._recommend(
                attacker["risk_score"]
            ),
        }

    def _recommend(self, risk_score):

        if risk_score >= 90:
            return (
                "Immediately block source IP "
                "and investigate."
            )

        if risk_score >= 70:
            return (
                "Block source IP and review logs."
            )

        return (
            "Monitor activity."
        )
