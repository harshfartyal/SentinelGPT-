def calculate_risk(alert):
    alert_type = alert.get("type")

    risk_scores = {
        "Suspicious Authentication Activity": 80,
        "Potential Privilege Escalation": 75,
        "Security Group Modification": 70,
        "Root Account Activity": 85,
        "CloudTrail Logging Modification": 90
    }

    score = risk_scores.get(alert_type, 30)

    # Increase authentication risk for repeated failures
    if alert_type == "Suspicious Authentication Activity":

        failed_attempts = alert.get(
            "failed_attempts",
            0
        )

        if failed_attempts >= 5:
            score = min(score + 10, 100)

    if score >= 70:
        severity = "HIGH"

    elif score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return score, severity