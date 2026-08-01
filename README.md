# Security Engineering Portfolio Project

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Stack: React + Vite](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-06b6d4)](https://vitejs.dev/)
[![Design: Apple + Microsoft Dark Glassmorphism](https://img.shields.io/badge/Design-Dark%20SOC%20Glassmorphism-10b981)]()

**Security Engineering Portfolio Project** is an enterprise-grade AI Cybersecurity Operations Center (SOC) platform designed for real-time log ingestion, threat detection, attack path explanation, MITRE ATT&CK mapping, interactive attack simulation, and automated remediation script generation (PowerShell, Bash, YARA, Sigma, Snort, Suricata).

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
### 7. 🛡️ Data Authenticity & Telemetry Provenance Architecture
- **Strict Operating Mode Isolation**: Supports `LIVE` mode (default) and `DEMO` mode.
- **Zero Fake Data in LIVE Mode**: Background synthetic flow generators are **disabled by default**. Empty live environments display honest empty states.
- **Immutable Provenance Metadata**: Every single event, flow, alert, and packet capture carries immutable provenance fields (`platformMode`, `telemetrySource`, `collectionMethod`, `isSynthetic`, `isSeeded`, `isReplay`, `collectorId`, `ingestionTimestamp`).
- **Visual Source Badges**: Color-coded badges (`LIVE SYSLOG`, `LIVE WEF`, `LIVE NETFLOW`, `UPLOADED PCAP`, `NMAP IMPORT`, `DEMO SYNTHETIC`, `DEMO SEEDED`) with hover tooltips for full auditability.

#### Truthful Implementation Status Matrix

| Capability | Status | Telemetry Provenance | Ingestion Path |
|---|---|---|---|
| Live Packet Capture (Npcap/libpcap) | **Implemented** | `NETFLOW_COLLECTOR` / `LIVE_CAPTURE` | BPF Frame Engine / Raw Socket |
| Zeek JSON Log Ingestion | **Implemented** | `ZEEK_LOG` | JSON Ingest (`conn`, `dns`, `http`, `ssl`) |
| Suricata EVE IDS Ingestion | **Implemented** | `SURICATA_EVE` | EVE JSON Stream (`alert`, `flow`, `dns`) |
| Live Syslog Server (RFC 3164/5424) | **Implemented** | `SYSLOG_COLLECTOR` | UDP 5514 / TCP 5515 Receiver |
| Windows Event Forwarding (WEF XML) | **Implemented** | `WEF_COLLECTOR` | HTTP 5516 WinRM XML Receiver |
| NetFlow v5 / v9 / IPFIX | **Implemented** | `NETFLOW_COLLECTOR` | UDP 2055 Binary Frame Decoder |
| Binary PCAP Packet Parser | **Implemented** | `PCAP_UPLOAD` | File Upload (`.pcap`, `.pcapng`) |
| Nmap Scan Import | **Implemented** | `NMAP_IMPORT` | File Import (XML / Standard) |
| Sigma Threat Detection Engine | **Implemented** | Detection Engine | Automatic Rule Pipeline |
| Synthetic Demo Generator | **DEMO Mode Only** | `SYNTHETIC_DEMO` | Controlled Simulation Service |

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
- **Node.js** v18+ & npm
- **PostgreSQL** 16+ running on `localhost:5432` with database `soc_db`

### Installation Steps

1. Clone or open the repository:
```bash
cd "e:\IT\Intelligent Enterprise Security Operations Platform"
```

2. Install frontend dependencies:
```bash
npm install
```

3. Install backend dependencies:
```bash
cd server && npm install
```

---

### 🖥️ Running the Backend (SOC Collector Engine)

Start the backend development server from the `server/` directory:

```powershell
PS E:\IT\Intelligent Enterprise Security Operations Platform\server> npm run dev
```

Expected output on successful startup:

```
[Telemetry Pipeline] Subscribing to queue channels (syslog, wef, netflow)...
=======================================================
[Intelligent Enterprise Security Operations Platform v3.0] Running on http://localhost:5000
[WebSocket] Live Telemetry Stream: ws://localhost:5000/ws/telemetry
[Prometheus] OpenMetrics Endpoint: http://localhost:5000/metrics
=======================================================
[DB] PostgreSQL connected successfully to soc_db on localhost:5432.
[DB] PostgreSQL schema verified and ready for live operations.
[Collector Lifecycle] Syslog-Server (syslog): Stopped ➔ Initializing
[Collector Lifecycle] Windows-Event-Collector (wef): Stopped ➔ Initializing
[Collector Lifecycle] NetFlow-IPFIX-Collector (netflow): Stopped ➔ Initializing
[Syslog UDP] Listening on port 5514
[Syslog TCP] Listening on port 5515
[WEF HTTP] Listening for Windows Event Forwarding XML on port 5516
[NetFlow UDP] Listening for NetFlow v5/v9/IPFIX on port 2055
[Collector Lifecycle] Syslog-Server (syslog): Initializing ➔ Running
[Collector Lifecycle] Windows-Event-Collector (wef): Initializing ➔ Running
[Collector Lifecycle] NetFlow-IPFIX-Collector (netflow): Initializing ➔ Running
```

#### Backend Service Endpoints

| Service | URL / Address | Protocol |
|---|---|---|
| REST API | `http://localhost:5000/api` | HTTP |
| WebSocket Telemetry Stream | `ws://localhost:5000/ws/telemetry` | WebSocket |
| Prometheus Metrics | `http://localhost:5000/metrics` | HTTP |
| Health Check | `http://localhost:5000/health` | HTTP |
| Collector Management | `http://localhost:5000/api/collectors/status` | HTTP |

#### Live Telemetry Collector Ports

| Collector | Port | Protocol |
|---|---|---|
| Syslog (RFC 3164 / 5424) | `5514` UDP / `5515` TCP | UDP & TCP |
| Windows Event Forwarding (WEF) | `5516` | HTTP (WinRM XML) |
| NetFlow v5 / v9 / IPFIX | `2055` | UDP Binary |

---

### 🌐 Running the Frontend (React Dashboard)

In a **separate terminal**, start the Vite development server from the project root:

```powershell
PS E:\IT\Intelligent Enterprise Security Operations Platform> npm run dev
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
