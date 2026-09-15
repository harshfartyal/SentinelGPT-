# SentinelGPT

SentinelGPT is a cloud security monitoring project developed as part of Minor Project-I.

The project analyzes AWS CloudTrail logs and looks for suspicious activities such as unusual login behavior, IAM permission changes, security group modifications, root account activity, and changes to CloudTrail logging.

It also assigns a risk score, maps alerts to MITRE ATT&CK techniques, performs basic threat hunting, and provides recommended response actions.

## Features

- CloudTrail log parsing
- Suspicious login detection
- IAM privilege change detection
- Security group change detection
- Root account activity detection
- CloudTrail logging change detection
- Rule-based risk scoring
- MITRE ATT&CK mapping
- Basic IP-based threat hunting
- Basic vulnerability/security-risk checks
- Incident response recommendations
- Streamlit dashboard
- Automated tests using pytest

## How it works

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

## Running the project

Install the dependencies:

python -m pip install -r requirements.txt

Run the main analysis:

python main.py

Run the dashboard:

python -m streamlit run dashboard\app.py

Run the tests:

python -m pytest

## Current Testing

The project currently contains automated tests for the main detection and risk-scoring functions.

8 tests currently pass.

## Current Data

The current version uses a manually created CloudTrail-formatted JSON file for testing.

The logs are simulated data and are not collected from a live AWS account.

Live AWS CloudTrail integration can be added in a future version.

## Limitations

This is currently a prototype for academic and learning purposes.

Some of the detection and vulnerability checks are rule-based and use a limited set of CloudTrail events. The threat-hunting functionality is also basic at this stage.

The LLM analyst component is currently implemented with local analysis logic. Actual LLM API integration is planned for a later stage.

## Future Improvements

- Live AWS CloudTrail integration
- More CloudTrail detection rules
- Better threat-hunting capabilities
- Threat intelligence integration
- More detailed vulnerability assessment
- Persistent storage
- LLM-assisted security analysis
- Support for additional cloud platforms

## Project

Harsh Fartyal


## Disclaimer

This project is developed for academic and educational purposes. The current implementation uses simulated CloudTrail data and should not be considered a production SOC system.

