# incident_response/responder.py

def generate_response(alert, severity):
    response_actions = []

    alert_type = alert.get("type")

    if alert_type == "Suspicious Authentication Activity":
        response_actions = [
            "Verify whether the login was legitimate.",
            "Review recent activity of the affected user.",
            "Check the source IP for additional suspicious activity.",
            "Consider resetting credentials if compromise is confirmed."
        ]

    elif alert_type == "Potential Privilege Escalation":
        response_actions = [
            "Review the IAM policy change.",
            "Verify whether the permission change was authorized.",
            "Check the user's recent AWS activity.",
            "Remove unauthorized permissions if compromise is confirmed."
        ]

    elif alert_type == "Security Group Modification":
        response_actions = [
            "Review the modified security group rule.",
            "Verify whether the network change was authorized.",
            "Check whether sensitive resources became publicly accessible.",
            "Revert the rule if it is confirmed to be malicious."
        ]

    elif alert_type == "Root Account Activity":
        response_actions = [
            "Verify whether the root account activity was authorized.",
            "Review all recent activity performed by the root account.",
            "Check for additional suspicious changes in the AWS account.",
            "Secure the root account and credentials if compromise is suspected."
        ]

    elif alert_type == "CloudTrail Logging Modification":
        response_actions = [
            "Verify whether the CloudTrail configuration change was authorized.",
            "Review recent activity performed by the user.",
            "Check whether logging was disabled or modified.",
            "Restore the intended CloudTrail configuration if the change was unauthorized."
        ]

    else:
        response_actions = [
            "Investigate the alert and verify whether the activity is legitimate."
        ]

    return response_actions