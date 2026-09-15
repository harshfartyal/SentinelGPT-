import sys
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

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
from threat_hunting.hunter import hunt_suspicious_ips
from vulnerability.vulnerability_scanner import scan_vulnerabilities
from incident_response.responder import generate_response


st.set_page_config(
    page_title="SentinelGPT SOC",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentinelGPT")
st.subheader("AI-Assisted Cloud Security Operations Center")

st.write(
    "Cloud Threat Detection • Threat Hunting • "
    "Vulnerability Assessment • Incident Response"
)


# ========================================
# LOAD LOGS
# ========================================

try:
    logs = load_cloudtrail_logs(
        str(
            PROJECT_ROOT
            / "data"
            / "sample_cloudtrail.json"
        )
    )

except Exception as error:

    st.error(
        f"Unable to load CloudTrail logs: {error}"
    )

    st.stop()


st.success(
    f"CloudTrail logs loaded successfully — "
    f"{len(logs)} events"
)


# ========================================
# SECURITY SCAN
# ========================================

st.header("🔍 Security Scan")

st.write(
    "Run the security analysis against the loaded "
    "CloudTrail events."
)


if st.button(
    "🚀 Run Security Scan",
    type="primary"
):

    st.session_state["scan_started"] = True


if not st.session_state.get(
    "scan_started",
    False
):

    st.info(
        "Click 'Run Security Scan' to start the analysis."
    )

    st.stop()


st.success("Security scan completed.")


# ========================================
# THREAT DETECTION
# ========================================

alerts = []

alerts.extend(
    detect_suspicious_login(logs)
)

alerts.extend(
    detect_privilege_changes(logs)
)

alerts.extend(
    detect_security_group_changes(logs)
)

alerts.extend(
    detect_root_account_activity(logs)
)

alerts.extend(
    detect_logging_changes(logs)
)


# ========================================
# PROCESS ALERTS
# ========================================

processed_alerts = []

for alert in alerts:

    score, severity = calculate_risk(alert)

    mitre_info = map_to_mitre(alert)

    response_actions = generate_response(
        alert,
        severity
    )

    processed_alerts.append(
        {
            "alert": alert,
            "score": score,
            "severity": severity,
            "mitre": mitre_info,
            "response": response_actions
        }
    )


# ========================================
# THREAT HUNTING
# ========================================

hunting_results = hunt_suspicious_ips(logs)


# ========================================
# VULNERABILITY ASSESSMENT
# ========================================

vulnerability_findings = scan_vulnerabilities(logs)


# ========================================
# SECURITY METRICS
# ========================================

high_count = 0
medium_count = 0
low_count = 0

for item in processed_alerts:

    if item["severity"] == "HIGH":
        high_count += 1

    elif item["severity"] == "MEDIUM":
        medium_count += 1

    else:
        low_count += 1


# ========================================
# SECURITY OVERVIEW
# ========================================

st.header("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "CloudTrail Events",
        len(logs)
    )

with col2:

    st.metric(
        "Security Alerts",
        len(processed_alerts)
    )

with col3:

    st.metric(
        "High Risk Alerts",
        high_count
    )

with col4:

    st.metric(
        "Security Findings",
        len(vulnerability_findings)
    )


# ========================================
# ALERT SEVERITY
# ========================================

st.header("🚨 Alert Severity")

severity_data = pd.DataFrame(
    {
        "Severity": [
            "HIGH",
            "MEDIUM",
            "LOW"
        ],
        "Alerts": [
            high_count,
            medium_count,
            low_count
        ]
    }
)

st.bar_chart(
    severity_data.set_index("Severity")
)


# ========================================
# CLOUDTRAIL EVENTS
# ========================================

st.header("📋 CloudTrail Events")

event_rows = []

for log in logs:

    event_rows.append(
        {
            "Time": log.get(
                "eventTime",
                "Unknown"
            ),

            "Event": log.get(
                "eventName",
                "Unknown"
            ),

            "Source": log.get(
                "eventSource",
                "Unknown"
            ),

            "Region": log.get(
                "awsRegion",
                "Unknown"
            ),

            "Source IP": log.get(
                "sourceIPAddress",
                "Unknown"
            ),

            "User": log.get(
                "userIdentity",
                {}
            ).get(
                "userName",
                "Unknown"
            )
        }
    )


events_df = pd.DataFrame(event_rows)

st.dataframe(
    events_df,
    use_container_width=True,
    hide_index=True
)


# ========================================
# THREAT HUNTING
# ========================================

st.header("🔎 Threat Hunting")

if hunting_results:

    for result in hunting_results:

        with st.expander(
            f"Suspicious IP: "
            f"{result['source_ip']}"
        ):

            st.write(
                f"**Event Count:** "
                f"{result['event_count']}"
            )

            st.write(
                "**Events:** "
                + ", ".join(result["events"])
            )

            st.write(
                "**Users:** "
                + ", ".join(result["users"])
            )

            st.write("**Reasons:**")

            for reason in result["reasons"]:

                st.write(
                    f"→ {reason}"
                )

else:

    st.success(
        "No suspicious IP activity found."
    )


# ========================================
# VULNERABILITY ASSESSMENT
# ========================================

st.header("⚠️ Vulnerability Assessment")

if vulnerability_findings:

    for finding in vulnerability_findings:

        with st.expander(
            f"{finding['severity']} | "
            f"{finding['type']}"
        ):

            st.write(
                f"**Event:** "
                f"{finding['event']}"
            )

            st.write(
                f"**Username:** "
                f"{finding['username']}"
            )

            st.write(
                f"**Source IP:** "
                f"{finding['source_ip']}"
            )

            st.write(
                f"**Description:** "
                f"{finding['description']}"
            )

            st.write(
                f"**Recommendation:** "
                f"{finding['recommendation']}"
            )

else:

    st.success(
        "No security findings found."
    )


# ========================================
# SECURITY ALERTS
# ========================================

st.header("🛑 Security Alerts")

if processed_alerts:

    selected_severity = st.selectbox(
        "Filter alerts by severity",
        [
            "ALL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ]
    )

    displayed_alerts = []

    for item in processed_alerts:

        if (
            selected_severity == "ALL"
            or item["severity"]
            == selected_severity
        ):

            displayed_alerts.append(item)


    if displayed_alerts:

        for number, item in enumerate(
            displayed_alerts,
            start=1
        ):

            alert = item["alert"]

            score = item["score"]

            severity = item["severity"]

            mitre_info = item["mitre"]

            response_actions = item["response"]


            with st.expander(
                f"Alert {number} | "
                f"{severity} | "
                f"{alert['type']} | "
                f"Risk {score}/100"
            ):

                st.subheader(
                    "Alert Information"
                )

                st.write(
                    f"**Type:** "
                    f"{alert['type']}"
                )

                st.write(
                    f"**Username:** "
                    f"{alert.get('username', 'Unknown')}"
                )

                st.write(
                    f"**Source IP:** "
                    f"{alert.get('source_ip', 'Unknown')}"
                )

                st.write(
                    f"**Event:** "
                    f"{alert.get('event', 'Unknown')}"
                )

                if "failed_attempts" in alert:

                    st.write(
                        f"**Failed Attempts:** "
                        f"{alert['failed_attempts']}"
                    )

                st.write(
                    f"**Risk Score:** "
                    f"{score}/100"
                )

                st.write(
                    f"**Severity:** "
                    f"{severity}"
                )

                st.write(
                    f"**Description:** "
                    f"{alert['description']}"
                )


                st.subheader(
                    "🎯 MITRE ATT&CK"
                )

                st.write(
                    f"**Technique ID:** "
                    f"{mitre_info['technique_id']}"
                )

                st.write(
                    f"**Technique:** "
                    f"{mitre_info['technique']}"
                )

                st.write(
                    f"**Tactic:** "
                    f"{mitre_info['tactic']}"
                )

                st.write(
                    f"**Reason:** "
                    f"{mitre_info['reason']}"
                )


                st.subheader(
                    "🛡️ Recommended Response"
                )

                for action in response_actions:

                    st.write(
                        f"→ {action}"
                    )

    else:

        st.info(
            "No alerts match the selected severity."
        )

else:

    st.success(
        "No suspicious activity detected."
    )


# ========================================
# SYSTEM STATUS
# ========================================

st.header("⚙️ System Status")

status_col1, status_col2 = st.columns(2)


with status_col1:

    st.success(
        "CloudTrail Parser — ONLINE"
    )

    st.success(
        "Threat Detection — ONLINE"
    )

    st.success(
        "Risk Engine — ONLINE"
    )

    st.success(
        "MITRE Mapper — ONLINE"
    )


with status_col2:

    st.success(
        "Threat Hunting — ONLINE"
    )

    st.success(
        "Vulnerability Scanner — ONLINE"
    )

    st.success(
        "Incident Response — ONLINE"
    )

    st.info(
        "LLM Analyst — Local analyst logic"
    )


st.divider()

st.caption(
    "SentinelGPT | Minor Project-I | "
    "AI-Assisted Cloud Security Operations Center"
)