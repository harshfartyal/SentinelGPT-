def analyze_incident(alert, score, severity, mitre_info):

    alert_type = alert.get("type")

    if alert_type == "Suspicious Authentication Activity":

        summary = (
            "Multiple failed login attempts were followed "
            "by a successful login. This may indicate "
            "possible credential misuse."
        )

        recommendation = (
            "Verify the login, investigate the source IP, "
            "review recent user activity, and reset credentials "
            "if compromise is confirmed."
        )

    elif alert_type == "Potential Privilege Escalation":

        summary = (
            "An IAM policy change was detected that may "
            "have increased the permissions of a user or role."
        )

        recommendation = (
            "Review the policy change, verify authorization, "
            "and remove unauthorized permissions if necessary."
        )

    elif alert_type == "Security Group Modification":

        summary = (
            "A security group rule was modified. "
            "This may change network access to cloud resources."
        )

        recommendation = (
            "Review the modified rule, verify authorization, "
            "and revert the change if it is unauthorized."
        )

    elif alert_type == "Root Account Activity":

        summary = (
            "Activity was detected using the AWS root account. "
            "Root account activity requires careful investigation."
        )

        recommendation = (
            "Verify the activity, review recent root actions, "
            "and secure the root account if compromise is suspected."
        )

    elif alert_type == "CloudTrail Logging Modification":

        summary = (
            "A CloudTrail logging configuration was modified. "
            "This may reduce visibility into cloud activity."
        )

        recommendation = (
            "Verify the change, investigate the responsible user, "
            "and restore the intended logging configuration "
            "if unauthorized."
        )

    else:

        summary = (
            "Suspicious cloud activity was detected "
            "and requires investigation."
        )

        recommendation = (
            "Review the alert details and verify whether "
            "the activity was authorized."
        )

    return {
        "summary": summary,
        "risk": f"Risk score: {score}/100 ({severity})",
        "mitre": (
            f"{mitre_info.get('technique_id')} - "
            f"{mitre_info.get('technique')}"
        ),
        "recommendation": recommendation
    }