import ipaddress

import requests


def lookup_ip(ip):

    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:

            return {
                "country": "Private Network",
                "city": "Local Lab",
                "isp": "Internal Network",
            }

    except Exception:
        pass

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5,
        )

        data = response.json()

        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
        }

    except Exception:

        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
        }
