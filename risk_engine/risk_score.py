# risk_engine/risk_score.py

def calculate_risk(alert):
    score = 0

    alert_type = alert.get("type")

    # Suspicious authentication
    if alert_type == "Suspicious Authentication Activity":
        failed_attempts = alert.get("failed_attempts", 0)

        if failed_attempts >= 2:
            score += 30

        if failed_attempts >= 5:
            score += 10

        score += 30
        score += 20

    # IAM privilege changes
    elif alert_type == "Potential Privilege Escalation":
        score += 20
        score += 20
        score += 10

    # Security group changes
    elif alert_type == "Security Group Modification":
        score += 20
        score += 20
        score += 10

    # Root account activity
    elif alert_type == "Root Account Activity":
        score += 40
        score += 30

    # CloudTrail logging changes
    elif alert_type == "CloudTrail Logging Modification":
        score += 40
        score += 30

    # Determine severity
    if score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity