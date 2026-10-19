# CyberShield — Python SOC Simulation

CyberShield is a Python-based Security Operations Center (SOC) simulation project that demonstrates security alert detection, incident management, evidence analysis, and incident-response workflows.

The project is designed for learning and demonstrating cybersecurity concepts through a command-line application, simulated security events, JSON-based storage, and automated unit tests.

## Features

### Security Detection
- **Login monitoring:** Detects suspicious login activity and potential brute-force attacks.
- **Data Loss Prevention (DLP):** Scans documents for configured sensitive-data patterns.
- **File integrity monitoring:** Establishes file-hash baselines and identifies file changes.

### Incident Management
- Correlates security alerts into incidents.
- Tracks incident status and investigation notes.
- Prevents duplicate incidents and supports ongoing attack correlation.
- Searches and filters incidents by available attributes.
- Calculates incident risk scores and prioritizes investigations.

### Evidence and Auditing
- Builds chronological security-event timelines.
- Correlates incidents with supporting evidence.
- Exports incident evidence in JSON and PDF formats.
- Uses SHA-256 hashes to verify exported evidence files.
- Records evidence-related audit events.

### SOC Dashboard and Response
- Displays incident and alert analytics.
- Summarizes incident severity, status, and threat information.
- Records simulated response actions such as acknowledging, escalating, containing, and resolving an incident.
- Supports viewing response-action history during the current application session.

> **Scope:** CyberShield is a learning and simulation project. Its response actions are recorded by the application and do not perform real endpoint isolation, account blocking, or other production security controls.

## Technology Stack

- Python
- Object-oriented programming
- JSON file storage
- `unittest` for automated testing
- ReportLab for PDF report generation
- SHA-256 file hashing

## Project Structure

```text
cybershield/
├── core/           # Alerts, incidents, detection engine, incident management
├── detectors/      # Login, DLP, and file-integrity detection
├── services/       # Reporting, evidence, analytics, filtering, risk, response
├── tests/          # Automated unit and integration tests
├── test_files/     # Sample files used for security scanning
├── data/           # Runtime JSON data (generated locally)
├── reports/        # Generated incident exports (generated locally)
├── main.py         # Command-line application entry point
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Python 3
- `pip`
- A terminal or command prompt

## Installation

Clone the repository and open its directory:

```bash
git clone https://github.com/chaitanyaponnam/cybershield.git
cd cybershield
```

Create and activate a virtual environment.

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run CyberShield

From the project root, with the virtual environment activated:

```bash
python main.py
```

Follow the interactive menu to run security scans, inspect incidents, explore evidence, review analytics, and record simulated response actions.

## Run the Tests

Run the complete automated test suite:

```bash
python -m unittest discover -s tests -v
```

The current development version has **175 passing automated tests**.

## Runtime Data

CyberShield stores application data as JSON files under `data/` and generates incident exports under `reports/`. These files are runtime artifacts and are excluded from Git by the project's `.gitignore`.

The response-action history is currently held in memory and is not retained across application restarts.

## Learning Objectives

This project demonstrates practical concepts in:

- Security event detection and alert processing
- Incident correlation and lifecycle management
- File integrity verification
- Evidence collection and correlation
- Audit logging and incident prioritization
- Unit and integration testing
- Modular Python application design

## Disclaimer

CyberShield is an educational simulation and is not a replacement for a production SIEM, EDR, DLP, or incident-response platform. Use only authorized test data and systems.
