# Network Intrusion Detection System (NIDS)

A real-time NIDS built with Python and Scapy that detects port scan attacks,
fires email alerts, and visualizes everything on a live Streamlit dashboard.

## Features
- Port Scan Detection in real time
- Severity scoring: LOW / MEDIUM / HIGH / CRITICAL
- Email alerts via Gmail
- Live Streamlit dashboard with Plotly charts
- SQLite logging of all packets and alerts

## Project Structure
```
nids/
├── nids.py           # Core detection engine
├── logger.py         # SQLite logging
├── alerts.py         # Email alerter
├── dashboard.py      # Streamlit dashboard
├── requirements.txt  # Dependencies
├── .env              # Email config
└── logs/nids.db      # Database (auto-created)
```

## Setup
```bash
pip3 install -r requirements.txt --break-system-packages
```

## Usage
```bash
# Start NIDS
sudo python3 nids.py -i wlp0s20f3

# Launch Dashboard
streamlit run dashboard.py
# Open http://localhost:8501

# Test with port scan
nmap -sT 127.0.0.1
```

## Resume Bullet Points
- Built real-time NIDS using Scapy detecting port scan attacks with configurable thresholds
- Implemented severity scoring (LOW/MEDIUM/HIGH/CRITICAL) based on scan intensity
- Integrated Gmail email alerts triggered automatically on attack detection
- Visualized live intrusion data on Streamlit dashboard with Plotly charts

## Author
Rishita Sharma — github.com/RISHITASHARMA01
