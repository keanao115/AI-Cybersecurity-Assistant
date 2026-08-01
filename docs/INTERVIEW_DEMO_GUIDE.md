# Interview Demonstration Guide

## Step-by-Step Technical Demonstration

This guide provides a structured walkthrough to demonstrate the platform during a technical interview or portfolio presentation.

---

### Step 1: Demonstrate LIVE Mode & Honest Empty State (1-2 mins)

1. Start the application in LIVE mode (`PLATFORM_MODE=LIVE`).
2. Open the browser at `http://localhost:3000`.
3. Point out the glowing emerald **`LIVE MODE`** badge in the top-right header:
   > *"Notice that the platform starts in LIVE mode by default. Synthetic data generation is completely disabled."*
4. Navigate to **Live Network Monitor** under LIVE MONITORING:
   > *"Because no NetFlow exporters have sent packets yet, the dashboard displays an honest empty state rather than fabricating fake random flows."*

---

### Step 2: Ingest Genuine Live Syslog Telemetry (2-3 mins)

1. Open a terminal and send a real Syslog message over UDP port 5514:
   ```bash
   echo "<86>Aug 01 02:00:00 server01 sshd[1234]: Failed password for invalid user admin from 10.0.0.99 port 41234" | nc -u 127.0.0.1 5514
   ```
2. Navigate to **Collector Management** or **SIEM Event Console**.
3. Point out the newly ingested event:
   - Event parsed into RFC 3164 format and matched by `LinuxSyslogParser`.
   - **`LIVE SYSLOG`** source badge is rendered.
   - Hover over the badge to inspect the provenance tooltip (`Source: SYSLOG_COLLECTOR`, `Collection: NETWORK_RECEIVER`, `Synthetic: No`).

---

### Step 3: Inspect Binary PCAP Upload & Provenance (2-3 mins)

1. Navigate to **Packet Inspector**.
2. Upload a sample `.pcap` capture file.
3. Show the parsed binary PCAP summary:
   - Ethernet, IPv4, TCP/UDP protocol distribution parsed in pure JS.
   - Provenance badge shows **`UPLOADED PCAP`** with original file name and session ID.

---

### Step 4: Switch to DEMO Mode (Controlled Demonstration) (2 mins)

1. Click **`Switch to Demo`** in the top header (if `ALLOW_RUNTIME_MODE_SWITCH=true`).
2. Point out the visual changes:
   - Header badge transitions to amber **`DEMO MODE`**.
   - Persistent banner appears across the screen warning: `CONTROLLED DEMONSTRATION ENVIRONMENT`.
   - Synthetic flow generator starts sending simulated events every 8 seconds, clearly labeled with **`DEMO SYNTHETIC`**.
   - Explain how live and demonstration datasets remain completely isolated.
