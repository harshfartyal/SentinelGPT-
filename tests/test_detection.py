from detection.threat_detector import (
    detect_suspicious_login,
    detect_privilege_changes,
    detect_security_group_changes,
    detect_root_account_activity,
    detect_logging_changes
)

from risk_engine.risk_score import calculate_risk

from threat_hunting.hunter import hunt_suspicious_ips

from vulnerability.vulnerability_scanner import (
    scan_vulnerabilities
)


def test_suspicious_login():

    logs = [
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            },
            "responseElements": {
                "ConsoleLogin": "Failure"
            }
        },
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            },
            "responseElements": {
                "ConsoleLogin": "Failure"
            }
        },
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            },
            "responseElements": {
                "ConsoleLogin": "Success"
            }
        }
    ]

    alerts = detect_suspicious_login(logs)

    assert len(alerts) == 1
    assert (
        alerts[0]["type"]
        == "Suspicious Authentication Activity"
    )
    assert alerts[0]["failed_attempts"] == 2


def test_privilege_escalation():

    logs = [
        {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    ]

    alerts = detect_privilege_changes(logs)

    assert len(alerts) == 1

    assert (
        alerts[0]["type"]
        == "Potential Privilege Escalation"
    )


def test_security_group_change():

    logs = [
        {
            "eventName":
                "AuthorizeSecurityGroupIngress",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    ]

    alerts = detect_security_group_changes(logs)

    assert len(alerts) == 1

    assert (
        alerts[0]["type"]
        == "Security Group Modification"
    )


def test_root_account_activity():

    logs = [
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "type": "Root",
                "userName": "Root"
            }
        }
    ]

    alerts = detect_root_account_activity(logs)

    assert len(alerts) == 1

    assert (
        alerts[0]["type"]
        == "Root Account Activity"
    )


def test_cloudtrail_logging_modification():

    logs = [
        {
            "eventName": "StopLogging",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user"
            }
        }
    ]

    alerts = detect_logging_changes(logs)

    assert len(alerts) == 1

    assert (
        alerts[0]["type"]
        == "CloudTrail Logging Modification"
    )


def test_high_risk_authentication():

    alert = {
        "type":
            "Suspicious Authentication Activity",
        "failed_attempts": 2
    }

    score, severity = calculate_risk(alert)

    assert score == 80
    assert severity == "HIGH"


def test_high_risk_root_activity():

    alert = {
        "type": "Root Account Activity"
    }

    score, severity = calculate_risk(alert)

    assert score == 85
    assert severity == "HIGH"


def test_high_risk_logging_modification():

    alert = {
        "type":
            "CloudTrail Logging Modification"
    }

    score, severity = calculate_risk(alert)

    assert score == 90
    assert severity == "HIGH"


def test_threat_hunting():

    logs = [
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        },
        {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        },
        {
            "eventName":
                "AuthorizeSecurityGroupIngress",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    ]

    results = hunt_suspicious_ips(logs)

    assert len(results) == 1
    assert results[0]["source_ip"] == "1.1.1.1"
    assert results[0]["event_count"] == 3
    assert len(results[0]["reasons"]) >= 1


def test_iam_vulnerability():

    logs = [
        {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    ]

    findings = scan_vulnerabilities(logs)

    assert len(findings) == 1

    assert (
        findings[0]["type"]
        == "IAM Permission Risk"
    )

    assert findings[0]["severity"] == "HIGH"


def test_network_vulnerability():

    logs = [
        {
            "eventName":
                "AuthorizeSecurityGroupIngress",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    ]

    findings = scan_vulnerabilities(logs)

    assert len(findings) == 1

    assert (
        findings[0]["type"]
        == "Network Security Risk"
    )


def test_cloudtrail_vulnerability():

    logs = [
        {
            "eventName": "StopLogging",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {
                "userName": "test-user"
            }
        }
    ]

    findings = scan_vulnerabilities(logs)

    assert len(findings) == 1

    assert (
        findings[0]["type"]
        == "CloudTrail Visibility Risk"
    )