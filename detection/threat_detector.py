def detect_suspicious_login(logs):
    alerts = []
    failed_attempts = {}

    for log in logs:
        event_name = log.get("eventName")
        ip_address = log.get("sourceIPAddress")
        username = log.get("userIdentity", {}).get(
            "userName",
            "Unknown"
        )
        result = log.get("responseElements", {}).get(
            "ConsoleLogin"
        )

        if event_name == "ConsoleLogin" and result == "Failure":

            key = (username, ip_address)

            failed_attempts[key] = (
                failed_attempts.get(key, 0) + 1
            )

        elif event_name == "ConsoleLogin" and result == "Success":

            key = (username, ip_address)

            if failed_attempts.get(key, 0) >= 2:

                alerts.append({
                    "type": "Suspicious Authentication Activity",
                    "severity": "HIGH",
                    "username": username,
                    "source_ip": ip_address,
                    "failed_attempts": failed_attempts[key],
                    "event": event_name,
                    "description": (
                        "Multiple failed login attempts were "
                        "followed by a successful login."
                    )
                })

    return alerts


def detect_privilege_changes(logs):
    alerts = []

    suspicious_actions = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy"
    ]

    for log in logs:

        event_name = log.get("eventName")

        if event_name in suspicious_actions:

            alerts.append({
                "type": "Potential Privilege Escalation",
                "severity": "HIGH",
                "username": log.get(
                    "userIdentity", {}
                ).get(
                    "userName",
                    "Unknown"
                ),
                "source_ip": log.get(
                    "sourceIPAddress",
                    "Unknown"
                ),
                "event": event_name,
                "description": (
                    "An IAM policy change was detected "
                    "that may grant additional permissions."
                )
            })

    return alerts


def detect_security_group_changes(logs):
    alerts = []

    suspicious_actions = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress"
    ]

    for log in logs:

        event_name = log.get("eventName")

        if event_name in suspicious_actions:

            alerts.append({
                "type": "Security Group Modification",
                "severity": "HIGH",
                "username": log.get(
                    "userIdentity", {}
                ).get(
                    "userName",
                    "Unknown"
                ),
                "source_ip": log.get(
                    "sourceIPAddress",
                    "Unknown"
                ),
                "event": event_name,
                "description": (
                    "A security group rule was modified, "
                    "which may change network access "
                    "to cloud resources."
                )
            })

    return alerts


def detect_root_account_activity(logs):
    alerts = []

    for log in logs:

        user_identity = log.get(
            "userIdentity",
            {}
        )

        if user_identity.get("type") == "Root":

            alerts.append({
                "type": "Root Account Activity",
                "severity": "HIGH",
                "username": "Root",
                "source_ip": log.get(
                    "sourceIPAddress",
                    "Unknown"
                ),
                "event": log.get(
                    "eventName",
                    "Unknown"
                ),
                "description": (
                    "Activity was performed using the "
                    "AWS root account. Root account activity "
                    "should be carefully reviewed."
                )
            })

    return alerts


def detect_logging_changes(logs):
    alerts = []

    suspicious_actions = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors"
    ]

    for log in logs:

        event_name = log.get("eventName")

        if event_name in suspicious_actions:

            alerts.append({
                "type": "CloudTrail Logging Modification",
                "severity": "HIGH",
                "username": log.get(
                    "userIdentity", {}
                ).get(
                    "userName",
                    "Unknown"
                ),
                "source_ip": log.get(
                    "sourceIPAddress",
                    "Unknown"
                ),
                "event": event_name,
                "description": (
                    "A CloudTrail logging configuration "
                    "was modified. This may reduce visibility "
                    "into cloud activity and should be investigated."
                )
            })

    return alerts