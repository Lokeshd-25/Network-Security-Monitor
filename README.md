# Network Security Monitoring & Threat Detection

A Python-based network security monitoring tool that analyzes network traffic from PCAP files and detects suspicious network activity using rule-based threat detection.

## Features

- PCAP and PCAPNG file analysis
- Live network packet capture
- Port scan detection
- Repeated connection attempt detection
- Possible SYN flood / connection burst detection
- HIGH and MEDIUM severity classification
- Configurable detection thresholds
- Network traffic statistics
- Protocol breakdown
- Threat details and findings
- Automatic security report generation
- Interactive Streamlit dashboard

## Technologies Used

- Python
- Scapy
- Streamlit
- TCP/IP Networking
- PCAP Analysis
- Kali Linux
- Git & GitHub

## How It Works

```text
Network Traffic / PCAP
          |
          v
     Packet Analysis
          |
          v
   Threat Detection Rules
          |
    +-----+-----+
    |     |     |
 Port   Repeated  SYN
 Scan   Attempts  Burst
    |     |     |
    +-----+-----+
          |
          v
    Severity Level
          |
          v
   Streamlit Dashboard
          |
          v
     Security Report

---

# 📸 Dashboard Screenshots

## 🚨 Detected Threats

![Detected Threats](detected-threats.png)

## ⚙️ Detection Settings

![Detection Settings](detection-settings.png)

## 📊 Network Statistics

![Network Statistics](network-statistics.png)
