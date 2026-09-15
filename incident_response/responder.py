def generate_response(alert, severity):

    response_actions = []

    alert_type = alert.get("type")

    if alert_type == "Suspicious Authentication Activity":

        response_actions = [
            "Verify whether the login was legitimate.",
            "Review recent activity of the affected user.",
            "Investigate the source IP for additional activity.",
            "Check for additional failed login attempts.",
            "Reset credentials if compromise is confirmed."
        ]

    elif alert_type == "Potential Privilege Escalation":

        response_actions = [
            "Review the IAM policy change.",
            "Verify whether the permission change was authorized.",
            "Review recent AWS activity by the affected user.",
            "Check whether excessive permissions were granted.",
            "Remove unauthorized permissions if necessary."
        ]

    elif alert_type == "Security Group Modification":

        response_actions = [
            "Review the modified security group rule.",
            "Verify whether the network change was authorized.",
            "Check whether sensitive resources became exposed.",
            "Identify the user who made the change.",
            "Revert the rule if it is confirmed to be malicious."
        ]

    elif alert_type == "Root Account Activity":

        response_actions = [
            "Verify whether the root account activity was authorized.",
            "Review all recent root account actions.",
            "Check for additional suspicious account changes.",
            "Investigate the source IP.",
            "Secure the root account if compromise is suspected."
        ]

    elif alert_type == "CloudTrail Logging Modification":

        response_actions = [
            "Verify whether the CloudTrail change was authorized.",
            "Identify the user who modified the configuration.",
            "Review recent activity by that user.",
            "Check whether logging was disabled or altered.",
            "Restore the intended logging configuration if unauthorized."
        ]

    else:

        response_actions = [
            "Investigate the alert.",
            "Verify whether the activity is legitimate.",
            "Review related cloud activity."
        ]

    return response_actions