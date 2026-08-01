# Suricata EVE JSON Integration Guide

## Overview

The platform ingests **Suricata IDS/IPS EVE JSON** events (`event_type: "alert"`, `"flow"`, `"dns"`, `"http"`, `"tls"`).

---

## Severity & Threat Score Mapping

| Suricata Severity | Platform Severity | Defensive Priority |
|---|---|---|
| Severity 1 | `Critical` | Immediate SOC Triage (P0) |
| Severity 2 | `High` | High Priority Investigation (P1) |
| Severity 3 | `Medium` | Operational Monitoring (P2) |
| Severity 4 | `Low` / `Info` | Informational Log |

---

## Ingestion API

```http
POST /api/suricata/eve
Content-Type: application/json

{
  "timestamp": "2026-08-01T10:15:22.000Z",
  "event_type": "alert",
  "src_ip": "185.220.101.5",
  "src_port": 4444,
  "dest_ip": "192.168.1.105",
  "dest_port": 49152,
  "proto": "TCP",
  "alert": {
    "signature": "ET MALWARE Suspicious Inbound Reverse Shell Traffic",
    "signature_id": 2012345,
    "severity": 1,
    "category": "A Network Trojan was detected"
  }
}
```
