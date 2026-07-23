from __future__ import annotations

import base64
import requests

from secureops.config import get_settings


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.virustotal_api_key

    def lookup_url(self, url: str) -> dict:
        if not self.api_key:
            return {
                "success": False,
                "error": "VirusTotal API key not configured."
            }

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().rstrip("=")

        response = requests.get(
            f"{self.BASE_URL}/urls/{url_id}",
            headers={
                "x-apikey": self.api_key,
            },
            timeout=10,
        )

        if response.status_code == 404:
            return {
                "success": False,
                "error": "URL has never been scanned by VirusTotal."
            }

        response.raise_for_status()

        data = response.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]

        return {
            "success": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation", 0),
            "categories": data.get("categories", {}),
            "analysis_date": data.get("last_analysis_date"),
        }
