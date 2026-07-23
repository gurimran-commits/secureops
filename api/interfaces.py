try:
    import psutil
except ImportError:  # pragma: no cover - depends on deployment extras
    psutil = None


def get_interfaces():
    if psutil is None:
        return []

    result = []

    for name, addrs in psutil.net_if_addrs().items():

        ip_address = None

        for addr in addrs:

            if addr.family == 2:  # AF_INET

                ip_address = addr.address
                break

        result.append(
            {
                "name": name,
                "ip": ip_address,
            }
        )

    return result
