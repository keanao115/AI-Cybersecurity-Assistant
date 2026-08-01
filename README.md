# Intelligent Enterprise Security Operations Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Stack: React + Vite](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-06b6d4)](https://vitejs.dev/)
[![Design: Apple + Microsoft Dark Glassmorphism](https://img.shields.io/badge/Design-Dark%20SOC%20Glassmorphism-10b981)]()

**Intelligent Enterprise Security Operations Platform** is an enterprise-grade AI Cybersecurity Operations Center (SOC) platform designed for real-time log ingestion, threat detection, attack path explanation, MITRE ATT&CK mapping, interactive attack simulation, and automated remediation script generation (PowerShell, Bash, YARA, Sigma, Snort, Suricata).

---

## 🌟 Key Highlights & Features

### 1. 📊 Executive SOC Dashboard
- **Comprehensive Security Scoring**: Overall (94), Network (90), Endpoints (88), Identity (96), Cloud (92), Email (98), Authentication (95).
- **Telemetry & Infrastructure Health**: Real-time CPU, RAM, Disk buffer, Palo Alto Firewall status, Antivirus update monitor.
- **Interactive Recharts Timelines**: Dynamic 24-hour threat vector timeline and severity breakdown pie chart.

### 2. 📜 Multi-Source Log & Vulnerability Parsing Engine
- **Windows Event Log**: XML, CSV, TXT (Event IDs `4625` Brute Force, `4688` Obfuscated PowerShell, `4720` Backdoor Local Account, `1102` Log Cleared).
- **Linux Auth & Syslog**: SSH Brute force, sudo privilege escalation (`stage2.sh`), OOM miner kills.
- **Firewall Telemetry**: Palo Alto, Cisco ASA dropped C2 beacon traffic on port `4444`.
- **Network Scanner (Nmap)**: XML & standard output parser (OS fingerprinting, MS17-010 EternalBlue vulnerability checks).
- **Vulnerability Scanner (Nessus/Qualys)**: CVSS 10.0 Log4j, CVSS 9.8 EternalBlue, exploit probability, patch priority (P0/P1).

### 3. ⚡ Live Attack Simulation Mode (Interview Highlight)
- Interactive 1-click simulation for **Brute Force**, **Obfuscated PowerShell C2 Payload**, **LockBit Ransomware Volume Shadow Deletion**, and **SQL Injection**.
- Streaming terminal logs and automated AI counter-measure triggers.

### 4. 🤖 SOC Analyst Copilot & Playbooks
- Guided incident response playbooks with step-by-step triage checklists and one-click host isolation triggers.

### 5. 📚 RAG Security Knowledge Base
- Embedded semantic search across **NIST SP 800-61 Rev. 2**, **OWASP Top 10**, **MITRE ATT&CK**, and **Windows Event ID References**.

### 6. 🛠️ Automated Mitigation Script Generator
- One-click copyable scripts:
  - **PowerShell**: Firewall rules, account disabling, process termination, SMBv1 hardening.
  - **Linux Bash**: IPTables drops, stage-2 shell kill, SSH hardening.
  - **YARA Rules**: Malware stager detection strings.
  - **Sigma Rules**: Windows process creation detection rules.
  - **Snort & Suricata Rules**: IDS/IPS packet inspection signatures.

---

## 🏗️ Architecture & Technology Stack

```
                                +-----------------------------------+
                                |    CyberMind AI User Dashboard    |
                                |  (Apple + Microsoft Glassmorphism) |
                                +-----------------+-----------------+
                                                  |
                 +--------------------------------+--------------------------------+
                 |                                |                                |
    +------------v------------+      +------------v------------+      +------------v------------+
    | Multi-Log Parser Engine |      | Live Attack Simulator   |      |  SOC Analyst Copilot   |
    | (Windows/Linux/Nmap/FW) |      | & Event Stream Console  |      | & Guided IR Playbooks   |
    +------------+------------+      +------------+------------+      +------------+------------+
                 |                                |                                |
                 +--------------------------------+--------------------------------+
                                                  |
                                +-----------------v-----------------+
                                |  CyberMind AI Intelligence Engine |
                                |  (Offline Rules + Gemini/OpenAI)  |
                                +-----------------+-----------------+
                                                  |
                   +------------------------------+------------------------------+
                   |                                                             |
      +------------v------------+                                   +------------v------------+
      | MITRE ATT&CK & CVE Map  |                                   | Remediation Generators  |
      | RAG Knowledge Engine    |                                   | (PS/Bash/YARA/Sigma)    |
      +-------------------------+                                   +-------------------------+
```

---

## ⚡ Quick Start & Running Locally

### Prerequisites
- Node.js (v18+) & npm

### Installation Steps

1. Clone or open the repository:
```bash
cd "e:\IT\Intelligent Enterprise Security Operations Platform"
```

2. Install dependencies:
```bash
npm install
```

3. Run the local development server:
```bash
npm run dev
```

4. Open your browser and navigate to:
```
http://localhost:3000
```

---

## 🐳 Docker Deployment Guide

To run CyberMind AI inside a containerized Docker environment:

```dockerfile
# Dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and start via Docker Compose:
```bash
docker-compose up -d --build
```

---

## 📜 License & Author

- **Project**: CyberMind AI Enterprise Platform
- **License**: MIT License
