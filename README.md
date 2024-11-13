# IDS Live Analysis Dashboard

This project is an **Intrusion Detection System (IDS)** dashboard for live analysis of security logs and attack trends. It displays real-time logs, a summary of detected attacks, alerts, and attack trends using visualizations (Charts.js). It helps in monitoring network activities and detecting potential threats.

## Features
- **Real-time Log Monitoring**: Continuously displays system logs for security events.
- **Attack Summary**: Displays the count of detected attack types like Brute Force, Port Scans, Phishing Attempts, etc.
- **Attack Trends**: Visual representation of attack trends using **Chart.js**.
- **Alerts System**: Highlights alerts for specific detected activities (e.g., phishing attempts or suspicious IP accesses).

## Technology Stack
- **Frontend**: HTML, CSS, JavaScript (Bootstrap, Chart.js)
- **Backend**: Python (Flask)
- **Others**: Bloom Filter, JSON

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/cybok10/IDS_LIVE_ANALYSIS.git

2. Install Dependencies

Ensure you have Python 3 and pip installed. Then, install the required Python libraries.

pip install -r requirements.txt

python ids_analysis.py

open browser ------- https://localhost/5050


/get_logs: Should return the last few logs.
/generate_report: Should return a summary of the attack statistics.
/get_alerts: Should return the most recent alerts.

