# SentinelGPT

SentinelGPT is a cloud security monitoring project developed as part of Minor Project-I.

The project analyzes AWS CloudTrail logs and identifies suspicious cloud activities such as unusual authentication behavior, IAM permission changes, security group modifications, root account activity, and CloudTrail logging changes.

It also performs basic threat hunting and security-risk assessment, assigns risk scores, maps alerts to MITRE ATT&CK techniques, and generates recommended incident response actions.

## Features

- CloudTrail log parsing
- Suspicious login detection
- IAM privilege change detection
- Security group change detection
- Root account activity detection
- CloudTrail logging modification detection
- Rule-based risk scoring
- MITRE ATT&CK mapping
- IP-based threat hunting
- Basic vulnerability/security-risk assessment
- Incident response recommendations
- Streamlit security dashboard
- Automated testing using pytest

## How It Works

CloudTrail Logs
      ↓
    Parser
      ↓
Threat Detection
      ↓
 Risk Scoring
      ↓
MITRE ATT&CK
      ↓
Threat Hunting / Vulnerability Assessment
      ↓
Incident Response
      ↓
   Dashboard

## Project Structure

SentinelGPT/
│
├── data/
│   └── sample_cloudtrail.json
│
├── parser/
│   └── cloudtrail_parser.py
│
├── detection/
│   ├── threat_detector.py
│   └── mitre_mapper.py
│
├── risk_engine/
│   └── risk_score.py
│
├── llm/
│   └── analyst.py
│
├── threat_hunting/
│   └── hunter.py
│
├── vulnerability/
│   └── vulnerability_scanner.py
│
├── incident_response/
│   └── responder.py
│
├── dashboard/
│   └── app.py
│
├── tests/
│   └── test_detection.py
│
├── main.py
├── requirements.txt
├── .gitignore
└── README.md

## Technologies

- Python
- Streamlit
- Pandas
- AWS CloudTrail
- MITRE ATT&CK
- Pytest

## Running the Project

Install dependencies:

python -m pip install -r requirements.txt

Run the command-line analysis:

python main.py

Run the dashboard:

python -m streamlit run dashboard\app.py

Run automated tests:

python -m pytest

## Current Data

The current version uses a manually created CloudTrail-formatted JSON file for testing.

The logs are simulated data and are not collected from a live AWS account.

## Current Detection Approach

The current security detection system uses rule-based logic.

It checks predefined CloudTrail events and activity patterns to identify potentially suspicious behavior.

Risk scoring is also rule-based, with different risk weights assigned to different alert types.

The LLM analyst component currently uses local analyst logic. Actual LLM API integration can be added later.

## Limitations

This is a prototype developed for academic and learning purposes.

The current implementation uses simulated CloudTrail data and a limited number of detection rules.

Threat hunting and vulnerability assessment are also basic and can be expanded in future versions.

## Future Improvements

- Live AWS CloudTrail integration
- More CloudTrail detection rules
- Advanced threat hunting
- Threat intelligence integration
- More detailed cloud security assessment
- Persistent storage
- LLM API integration
- Support for AWS, Azure and GCP
- Improved security analytics

## Project

Harsh Fartyal

## Disclaimer

This project is developed for academic and educational purposes.

The current implementation uses simulated CloudTrail data and should not be considered a production SOC system.