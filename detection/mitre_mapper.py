# detection/mitre_mapper.py

def map_to_mitre(alert):

    alert_type = alert.get("type")

    if alert_type == "Suspicious Authentication Activity":
        return {
            "technique_id": "T1078",
            "technique": "Valid Accounts",
            "tactic": (
                "Initial Access / Persistence / "
                "Privilege Escalation / Defense Evasion"
            ),
            "reason": (
                "The successful authentication after repeated failures "
                "may indicate possible misuse of valid credentials."
            )
        }

    elif alert_type == "Potential Privilege Escalation":
        return {
            "technique_id": "T1098",
            "technique": "Account Manipulation",
            "tactic": "Persistence / Privilege Escalation",
            "reason": (
                "An IAM policy change may modify account permissions "
                "and potentially provide additional privileges."
            )
        }

    elif alert_type == "Security Group Modification":
        return {
            "technique_id": "T1562.007",
            "technique": "Disable or Modify Cloud Firewall",
            "tactic": "Defense Evasion",
            "reason": (
                "A security group rule was modified, which may alter "
                "cloud network security controls and allow unintended access."
            )
        }

    elif alert_type == "Root Account Activity":
        return {
            "technique_id": "T1078.004",
            "technique": "Valid Accounts: Cloud Accounts",
            "tactic": "Initial Access / Persistence",
            "reason": (
                "Use of a cloud root account may indicate the use of "
                "high-privilege valid credentials and should be investigated."
            )
        }

    elif alert_type == "CloudTrail Logging Modification":
        return {
            "technique_id": "T1562.001",
            "technique": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "reason": (
                "Modification of CloudTrail logging may reduce security "
                "visibility and could be used to evade detection."
            )
        }

    return {
        "technique_id": "N/A",
        "technique": "No MITRE mapping",
        "tactic": "N/A",
        "reason": "No matching technique identified."
    }