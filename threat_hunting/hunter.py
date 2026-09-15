def hunt_suspicious_ips(logs):
    ip_activity = {}

    for log in logs:
        ip_address = log.get("sourceIPAddress")

        if not ip_address:
            continue

        if ip_address not in ip_activity:
            ip_activity[ip_address] = {
                "event_count": 0,
                "events": [],
                "users": set()
            }

        ip_activity[ip_address]["event_count"] += 1

        event_name = log.get("eventName", "Unknown")
        username = log.get("userIdentity", {}).get(
            "userName",
            "Unknown"
        )

        ip_activity[ip_address]["events"].append(event_name)
        ip_activity[ip_address]["users"].add(username)

    results = []

    for ip_address, activity in ip_activity.items():

        event_count = activity["event_count"]
        events = activity["events"]
        users = activity["users"]

        reasons = []

        if event_count >= 3:
            reasons.append(
                "IP generated multiple CloudTrail events."
            )

        sensitive_events = [
            "AttachUserPolicy",
            "AuthorizeSecurityGroupIngress",
            "StopLogging",
            "DeleteTrail",
            "UpdateTrail",
            "PutEventSelectors"
        ]

        sensitive_activity = [
            event for event in events
            if event in sensitive_events
        ]

        if sensitive_activity:
            reasons.append(
                "IP performed sensitive cloud security actions."
            )

        if len(set(events)) >= 3:
            reasons.append(
                "IP performed multiple different types of actions."
            )

        if len(users) > 1:
            reasons.append(
                "IP was associated with multiple users."
            )

        if reasons:
            results.append({
                "source_ip": ip_address,
                "event_count": event_count,
                "events": list(set(events)),
                "users": list(users),
                "reasons": reasons
            })

    return results