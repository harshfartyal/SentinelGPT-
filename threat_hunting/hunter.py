def hunt_suspicious_ips(logs):
    suspicious_ips = {}

    for log in logs:
        ip_address = log.get("sourceIPAddress")

        if ip_address:
            suspicious_ips[ip_address] = suspicious_ips.get(ip_address, 0) + 1

    results = []

    for ip_address, count in suspicious_ips.items():

        if count >= 3:
            results.append({
                "source_ip": ip_address,
                "event_count": count,
                "reason": "IP generated multiple CloudTrail events."
            })

    return results