from urllib.parse import urlparse
import re

from secureops.threatintel.virustotal import VirusTotalClient

class PhishingDetector:

    SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "secure",
        "security",
        "update",
        "account",
        "bank",
        "paypal",
        "password",
        "signin",
        "confirm",
        "wallet",
        "billing",
    ]

    KNOWN_BRANDS = [
        "paypal",
        "google",
        "microsoft",
        "amazon",
        "facebook",
        "apple",
    ]

    def analyze(self, url):

        score = 0
        reasons = []

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Long URL
        if len(url) > 75:
            score += 15
            reasons.append(
                "long-url"
            )

        # Too many subdomains
        if domain.count(".") >= 3:
            score += 15
            reasons.append(
                "many-subdomains"
            )

        # Excessive hyphens
        if domain.count("-") >= 2:
            score += 20
            reasons.append(
                "many-hyphens"
            )

        # Suspicious keywords
        for keyword in self.SUSPICIOUS_KEYWORDS:

            if keyword in url.lower():

                score += 15

                reasons.append(
                    f"keyword:{keyword}"
                )

        # IP Address URL
        if re.match(
            r"^\d+\.\d+\.\d+\.\d+$",
            domain,
        ):
            score += 30

            reasons.append(
                "ip-address-url"
            )

        # Missing HTTPS
        if not url.lower().startswith(
            "https://"
        ):
            score += 20

            reasons.append(
                "no-https"
            )

        # Typosquatting detection
        for brand in self.KNOWN_BRANDS:

            typo_1 = brand.replace(
                "o",
                "0"
            )

            typo_2 = brand.replace(
                "l",
                "1"
            )

            if (
                typo_1 in domain
                or typo_2 in domain
            ):
                score += 40

                reasons.append(
                    f"typosquatting:{brand}"
                )

        # Final verdict
        if score >= 70:
            verdict = "phishing"

        elif score >= 40:
            verdict = "suspicious"

        else:
            verdict = "safe"
        vt = VirusTotalClient()
        try:
            vt_result = vt.lookup_url(url)
        except Exception:
            vt_result = {
                "success": False,
                "error": "VirusTotal lookup failed."
            }
        final_verdict = verdict
        confidence = min(score + 20, 95)
        if vt_result.get("success"):
        
            malicious = vt_result.get("malicious", 0)
            suspicious = vt_result.get("suspicious", 0)

            if malicious >= 10:
                final_verdict = "critical"
                confidence = 99

            elif malicious >= 3:
                final_verdict = "malicious"
                confidence = 97

            elif suspicious >= 5 and verdict == "safe":
                final_verdict = "suspicious"
                confidence = 90

        return {
            "url": url,
        
            "heuristic": {
                "risk_score": min(score, 100),
                "verdict": verdict,
                "reasons": reasons,
            },

            "virustotal": vt_result,

            "final_verdict": final_verdict,
            "confidence": confidence,
        }
