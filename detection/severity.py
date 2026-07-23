def calculate_severity(packet_count: int) -> str:
    if packet_count < 100:
        return "LOW"
    elif packet_count < 500:
        return "MEDIUM"
    elif packet_count < 1000:
        return "HIGH"
    return "CRITICAL"
