class ThreatReputation:

    KNOWN_MALICIOUS_IPS = {
        "192.168.100.10": {
            "reputation": "Lab Attacker",
            "confidence": 100,
        },
        "185.220.101.1": {
            "reputation": "Tor Exit Node",
            "confidence": 90,
        },
        "45.95.147.10": {
            "reputation": "Known Scanner",
            "confidence": 95,
        },
        "198.51.100.50": {
            "reputation": "Botnet Controller",
            "confidence": 99,
        },
    }

    def lookup(self, ip):

        if ip in self.KNOWN_MALICIOUS_IPS:
            return self.KNOWN_MALICIOUS_IPS[ip]

        return {
            "reputation": "Unknown",
            "confidence": 0,
        }
