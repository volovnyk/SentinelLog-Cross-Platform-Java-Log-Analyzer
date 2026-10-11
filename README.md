# SentinelLog — Cross‑Platform Java Log Analyzer

SentinelLog is a cross‑platform log analysis tool written entirely in Java.  
It supports both **Linux syslog** and **Windows Event XML** formats, providing  
event classification, SSH brute‑force detection, statistical summaries,  
JSON reporting, and a clean CLI interface.

This project is designed for system administrators, security engineers,  
and developers who need a lightweight, dependency‑free log analysis tool.

---

## ✨ Features

### 🔹 Cross‑Platform Log Parsing
- Linux syslog (`/var/log/auth.log`, `/var/log/syslog`, etc.)
- Windows Event Viewer XML exports (`.evtx → .xml`)
- Automatic format detection

### 🔹 Event Classification
SentinelLog categorizes events into:
- AUTH_FAILURE  
- AUTH_SUCCESS  
- SECURITY_ALERT  
- SYSTEM  
- NETWORK  
- APPLICATION  

### 🔹 SSH Brute‑Force Detection
Detects brute‑force attempts using:
- Sliding time window  
- Threshold‑based detection  
- IP extraction  
- Duplicate alert suppression  

### 🔹 Detailed Statistics
- Total events  
- Category distribution  
- Log level distribution  
- Authentication success/failure ratio  
- Peak activity hour  
- Errors by hour  
- Top log sources  

### 🔹 JSON Reporting
Generate machine‑readable JSON summaries for automation or SIEM ingestion.

---

## 📦 Installation

Clone the repository:

