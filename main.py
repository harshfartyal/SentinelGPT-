# main.py

from parser.cloudtrail_parser import load_cloudtrail_logs

from detection.threat_detector import (
    detect_suspicious_login,
    detect_privilege_changes,
    detect_security_group_changes,
    detect_root_account_activity,
    detect_logging_changes
)

from risk_engine.risk_score import calculate_risk
from detection.mitre_mapper import map_to_mitre
from llm.analyst import analyze_incident
from threat_hunting.hunter import hunt_suspicious_ips
from vulnerability.vulnerability_scanner import scan_vulnerabilities
from incident_response.responder import generate_response


print("========================================")
print("       SENTINELGPT SECURITY SOC")
print("========================================")


logs = load_cloudtrail_logs("data/sample_cloudtrail.json")

print("\nCloudTrail logs loaded successfully!")
print("Total events:", len(logs))


# ==============================
# THREAT HUNTING
# ==============================

hunting_results = hunt_suspicious_ips(logs)

print("\nThreat Hunting Results")
print("----------------------")

if hunting_results:
    for result in hunting_results:
        print("\n🔎 SUSPICIOUS IP")
        print("Source IP:", result["source_ip"])
        print("Event Count:", result["event_count"])
        print("Reason:", result["reason"])
else:
    print("No suspicious IP activity found.")


# ==============================
# VULNERABILITY ASSESSMENT
# ==============================

vulnerability_findings = scan_vulnerabilities(logs)

print("\nVulnerability Assessment")
print("------------------------")

if vulnerability_findings:
    for finding in vulnerability_findings:
        print("\n⚠️ VULNERABILITY FINDING")
        print("Type:", finding["type"])
        print("Severity:", finding["severity"])
        print("Event:", finding["event"])
        print("Source IP:", finding["source_ip"])
        print("Description:", finding["description"])
else:
    print("No vulnerabilities found.")


# ==============================
# THREAT DETECTION
# ==============================

alerts = detect_suspicious_login(logs)

privilege_alerts = detect_privilege_changes(logs)
alerts.extend(privilege_alerts)

security_group_alerts = detect_security_group_changes(logs)
alerts.extend(security_group_alerts)

root_alerts = detect_root_account_activity(logs)
alerts.extend(root_alerts)

logging_alerts = detect_logging_changes(logs)
alerts.extend(logging_alerts)


print("\nThreat Detection Results")
print("------------------------")


if alerts:

    for alert in alerts:

        print("\n🚨 SECURITY ALERT")

        print("Type:", alert["type"])
        print("Username:", alert["username"])
        print("Source IP:", alert["source_ip"])

        if "failed_attempts" in alert:
            print("Failed Attempts:", alert["failed_attempts"])

        if "event" in alert:
            print("Event:", alert["event"])

        print("Description:", alert["description"])


        # ==============================
        # RISK SCORING
        # ==============================

        score, severity = calculate_risk(alert)

        print("Risk Score:", score, "/ 100")
        print("Severity:", severity)


        # ==============================
        # MITRE ATT&CK
        # ==============================

        mitre_info = map_to_mitre(alert)

        print("\nMITRE ATT&CK Mapping")
        print("--------------------")

        print("Technique ID:", mitre_info["technique_id"])
        print("Technique:", mitre_info["technique"])
        print("Tactic:", mitre_info["tactic"])
        print("Reason:", mitre_info["reason"])


        # ==============================
        # LLM SECURITY ANALYST
        # ==============================

        analysis = analyze_incident(
            alert,
            score,
            severity,
            mitre_info
        )

        print("\nLLM Security Analyst")
        print("--------------------")

        print("Summary:", analysis["summary"])
        print("Risk:", analysis["risk"])
        print("MITRE:", analysis["mitre"])
        print("Recommendation:", analysis["recommendation"])


        # ==============================
        # INCIDENT RESPONSE
        # ==============================

        response_actions = generate_response(
            alert,
            severity
        )

        print("\nIncident Response")
        print("-----------------")

        for action in response_actions:
            print("→", action)

else:
    print("No suspicious activity detected.")


print("\n========================================")
print("       SENTINELGPT ANALYSIS COMPLETE")
print("========================================")