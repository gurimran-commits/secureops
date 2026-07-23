# 🛡 SecureOps – Intelligent Cyber Defense & Mini Security Operations Center (SOC)

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-orange)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue)
![License](https://img.shields.io/badge/License-Educational-red)

---

# Overview

SecureOps is a Python-based intelligent cyber defense platform that simulates the core functionality of a modern Security Operations Center (SOC).

It performs real-time network monitoring, attack detection, threat intelligence analysis, firewall automation, phishing detection, incident reporting, and security visualization through a modern desktop dashboard.

The project is designed as a practical cybersecurity platform for learning SOC operations and incident response.

---

# Key Features

## 🔐 Authentication System

- Secure administrator login
- First-time administrator account creation
- Password hashing using bcrypt
- Change password functionality
- Session management
- Logout support

---

## 📡 Live Network Monitoring

- Real-time packet capture using Scapy
- Live traffic monitoring
- Packets Per Second (PPS)
- Top Talkers
- Protocol distribution
- Network statistics
- Interface selection

---

## 🚨 Attack Detection

- DDoS Detection
- Port Scan Detection
- Brute Force Detection
- Traffic anomaly detection
- Protocol flood detection
- Risk score generation
- Confidence scoring

---

## 🌍 Threat Intelligence

- Malicious IP tracking
- Geo-IP lookup
- Country & City identification
- ISP identification
- Reputation scoring
- Threat history

---

## 🧠 Correlation Engine

- Attack correlation
- Incident timeline
- Multi-event tracking
- Threat campaign visualization

---

## 🛡 Firewall Management

- Automatic IP blocking
- Manual block/unblock
- Firewall rule management
- Firewall rule clearing
- Live firewall status

---

## 🎣 Phishing Detection

- URL phishing analysis
- Risk assessment
- Detection API
- Dashboard integration

---

## 📄 Incident Reporting

- PDF Incident Reports
- Latest Incident Report
- Alert history
- Report generation
- Local time (IST) timestamps

---

## 📊 Dashboard

- Modern PyQt6 interface
- Live metrics
- Traffic visualization
- Security score
- Threat level indicator
- Alert management
- Firewall management
- Threat Intelligence viewer
- Correlation viewer
- Settings page
- Authentication management

---

## ⚙ Settings

- Detection thresholds
- Refresh interval
- Interface selection
- Dashboard preferences
- Change password
- Logout

---

# Technologies Used

- Python 3.11+
- FastAPI
- PyQt6
- SQLite
- Scapy
- bcrypt
- ReportLab
- Pandas
- NumPy
- PyQtGraph
- Pydantic
- psutil
- iptables
- Nmap
- hping3

---

# Project Structure

```
SecureOps/
│
├── secureops/
│   ├── analysis/
│   ├── api/
│   ├── auth/
│   ├── capture/
│   ├── correlation/
│   ├── detection/
│   ├── gui/
│   ├── phishing/
│   ├── reporting/
│   ├── response/
│   ├── storage/
│   ├── main.py
│   └── config.py
│
├── data/
├── reports/
├── tests/
├── requirements.txt
└── README.md
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/gurimran-commits/SecureOps.git
cd SecureOps
```

---

## Create Virtual Environment

### Linux

```bash
python3 -m venv secureops-env
source secureops-env/bin/activate
```

### Windows

```bash
python -m venv secureops-env
secureops-env\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running SecureOps

## Start Backend API

```bash
python3 -m uvicorn secureops.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Start SecureOps

```bash
python -m secureops.gui.login
```

> **Note:** SecureOps should always be launched through the login screen.

---
user name and password -- user name - admin , password - 282000

you can change password from settings of dashboard
---
# Default Setup

On first launch:

- Create the administrator account.
- Set a secure password.
- Login to access the SecureOps dashboard.

---

# Testing

## DDoS Detection

```bash
sudo hping3 -S -p 80 --flood <TARGET_IP>
```

---

## Port Scan Detection

```bash
sudo nmap -sS -Pn -T5 -p 1-1000 <TARGET_IP>
```

---

## Brute Force Detection

```bash
for i in {1..30}; do
ssh \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
-o ConnectTimeout=1 \
invaliduser@<TARGET_IP> exit
done
```

---

## Phishing Detection

Use the Phishing Detection page inside the dashboard or call:

```
POST /api/phishing/check
```

---

# REST API

| Endpoint | Description |
|-----------|-------------|
| /api/health | System Health |
| /api/metrics | Live Metrics |
| /api/alerts | Alert List |
| /api/firewall/rules | Firewall Rules |
| /api/firewall/block | Block IP |
| /api/firewall/unblock | Unblock IP |
| /api/firewall/clear | Clear Firewall |
| /api/report/latest | Latest Report |
| /api/report/pdf | Generate PDF |
| /api/phishing/check | URL Phishing Detection |
| /api/interfaces | Available Interfaces |

---

# Security Features

- Administrator Authentication
- Password Hashing (bcrypt)
- Session Management
- API Key Protection
- Automatic Firewall Response
- Threat Intelligence
- Incident Logging
- Secure PDF Reporting

---

# Future Enhancements

- Machine Learning Detection
- SIEM Integration
- Email Alerts
- Web Dashboard
- Docker Deployment
- Multi-user Authentication
- RBAC (Role-Based Access Control)
- Threat Feed Integration
- Advanced IDS Signatures

---

# Author

**Gursimran Singh**

B.Tech – Computer Science Engineering

Cybersecurity Project

---
# License

This project is developed for educational and research purposes.
