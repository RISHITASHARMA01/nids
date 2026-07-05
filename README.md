# Network Intrusion Detection System (NIDS)

A real-time NIDS built with Python and Scapy that detects port scan attacks,
fires email alerts, and visualizes everything on a live Streamlit dashboard.

## Features
- Real-time port scan detection with configurable thresholds
- Severity scoring: LOW / MEDIUM / HIGH / CRITICAL
- Email alerts via Gmail
- Live Streamlit dashboard with Plotly charts
- SQLite logging with WAL mode (dashboard reads while NIDS writes without blocking)

## Project Structure
```
nids/
├── nids.py           # Core detection engine
├── logger.py         # SQLite logging (WAL mode, batched writes)
├── alerts.py         # Email alerter
├── dashboard.py      # Streamlit dashboard
├── requirements.txt  # Dependencies
├── .env              # Email config (not committed)
└── logs/nids.db      # Database (auto-created, not committed)
```

## Setup
```bash
pip3 install -r requirements.txt --break-system-packages
```

Configure email alerts in `.env`:
```
EMAIL_SENDER=you@gmail.com
EMAIL_PASSWORD=your_16_digit_app_password
EMAIL_RECEIVER=you@gmail.com
```
Get an app password at `myaccount.google.com/security` → App Passwords.

## Usage

**Find your network interface:**
```bash
ip link show        # Linux
ifconfig            # Mac
```

**Start NIDS:**
```bash
sudo python3 nids.py -i <interface>
```

**All flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `-i` / `--interface` | `wlp0s20f3` | Network interface to monitor |
| `-t` / `--threshold` | `10` | Unique ports before alerting |
| `-w` / `--time-window` | `5` | Detection window in seconds |
| `-c` / `--cooldown` | `60` | Seconds before re-alerting same IP |

**Example — stricter settings:**
```bash
sudo python3 nids.py -i eth0 -t 5 -w 10 -c 120
```

**Launch Dashboard:**
```bash
streamlit run dashboard.py
# Open http://localhost:8501
```

**Test with a port scan:**
```bash
nmap -sT 127.0.0.1
```

## Resume Bullet Points
- Built real-time NIDS using Scapy detecting port scan attacks with configurable thresholds
- Implemented severity scoring (LOW/MEDIUM/HIGH/CRITICAL) based on scan intensity
- Integrated Gmail email alerts triggered automatically on attack detection
- Visualized live intrusion data on Streamlit dashboard with Plotly charts

## Author
Rishita Sharma — github.com/RISHITASHARMA01
