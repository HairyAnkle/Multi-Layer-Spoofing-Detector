# 🛡️ AI-Based Multi-Layer Spoofing Detection System

A desktop-based **Network Forensic and Spoofing Detection System** designed to detect **ARP, DNS, and IP spoofing attacks** using a **Hybrid Machine Learning model (Random Forest + XGBoost)**.

This system integrates **PCAP analysis**, **Dockerized ML inference**, **SQLite forensic storage**, **SHA-256 chain-of-custody hashing**, and **HTML / JSON forensic report generation**, following digital forensics best practices.

---

## 📐 System Architecture Overview

The system follows a **Three-Tier Architecture**:

### 1️⃣ Presentation Tier
- C# WPF Desktop Application  
- Displays detection results, alerts, and summaries  
- Generates forensic reports (HTML & JSON)

### 2️⃣ Application Tier
- Dockerized **CICFlowMeter** (feature extraction)
- Dockerized **ML Inference Engine** (RF + XGBoost)
- Python backend (inference-only, no training)

### 3️⃣ Data Tier
- SQLite database for forensic persistence
- SHA-256 hashing for integrity & chain-of-custody
- Stored results retrieved for reporting

---

## 🧰 Technology Stack

```
+--------------------+-------------------------------------------------------------+
|     Component      |                         Technology                          |
+--------------------+-------------------------------------------------------------+
| UI                 | C# WPF (.NET)                                               |
| ML Backend         | Python 3.13                                                 |
| ML Models          | Random Forest, XGBoost                                      |
| Feature Extraction | CICFlowMeter (https://github.com/GintsEngelen/CICFlowMeter) |
| Containers         | Docker                                                      |
| Database           | SQLite                                                      |
| Hashing            | SHA-256                                                     |
| Reports            | HTML, JSON                                                  |
+--------------------+-------------------------------------------------------------+
```

---

## 📁 Project Structure

```
Multi-Layer-Spoofing-Detector/
│
├── integration/
│   ├── backend/
│   │   ├── spoofing_detector.py
│   │   ├── cic_preprocessor.py
│   │
│   ├── models/
│   │   └── RFandXGBoost.pkl
│   │
│   ├── docker/
│   │   └── Dockerfile
│
├── data/
│   ├── ForensicsRepository.cs
│   ├── schema.sql
│
├── reports/
│   ├── html/
│   └── json/
│
├── MainWindow.xaml
├── MainWindow.xaml.cs
├── MLIntegration.cs
├── build-all.ps1
└── README.md
```

---

## ⚙️ Prerequisites

### Required Software
- Windows 10 / 11
- Docker Desktop (WSL2 enabled)
- .NET SDK 6 or later
- PowerShell
- Python 3.13 (for debugging only)

### Verify Docker Installation
```powershell
docker --version
docker info
```

---

## 🚀 Step-by-Step Setup Guide

### Step 1: Open the Project
Open the `Multi-Layer-Spoofing-Detector` folder in **Visual Studio**.

---

### Step 2: Build Docker Images
```powershell
.\build-all.ps1
```

---

### Step 3: Verify Images
```powershell
docker images
```

---

### Step 4: Initialize Database
The SQLite database is auto-created on first run.

---

### Step 5: Run the Application
Press **Run** in Visual Studio.

---

## 🧪 Usage

1. Upload PCAP  
2. Run Analysis  
3. View Results  
4. Export HTML / JSON Reports  

Reports are saved under:
```
reports/html/
reports/json/
```

---

## 🔐 Chain of Custody
- PCAP hashed with SHA-256
- Reports hashed after generation
- Hashes stored in SQLite and embedded in reports

Each analysis creates a unique Case ID:
```
SPOOF-YYYYMMDD-HHMMSS
```
---

## 🗄️ Data Persistence (SQLite)
Stored per case:
- Case Metadata
- Threat Alerts
- Analysis Results
- Hash Records (PCAP & Reports)

---

## 🎓 Academic Context
Designed for Digital Forensics and Cybersecurity research.

## 👨‍💻 Author
**Cristian Ogena**
Computer Science – Digital Forensics
Multi-Layer Spoofing Detection System
