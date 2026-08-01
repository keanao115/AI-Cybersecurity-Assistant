# Zeek Telemetry Integration Guide

## Overview

The platform ingests structured JSON logs produced by **Zeek** (formerly Bro) network security monitor deployments:
- `conn.log` — TCP/UDP/ICMP connection state records
- `dns.log` — DNS queries, responses, and RCODEs
- `http.log` — HTTP requests, methods, URIs, user agents
- `ssl.log` — TLS Client/Server Hello parameters and SNI
- `notice.log` — Zeek script detection alerts

---

## Provenance Mapping

Every ingested Zeek record receives:
```json
{
  "platformMode": "LIVE",
  "telemetrySource": "ZEEK_LOG",
  "collectionMethod": "FILE_IMPORT",
  "isSynthetic": false,
  "collectorId": "zeek-sensor-conn"
}
```

---

## Ingestion API

```http
POST /api/zeek/ingest
Content-Type: application/json

{
  "logType": "conn",
  "entry": {
    "ts": 1722490000.12,
    "uid": "CHwBsb1e65oGZ70u7",
    "id.orig_h": "192.168.1.105",
    "id.orig_p": 54320,
    "id.resp_h": "10.0.0.1",
    "id.resp_p": 445,
    "proto": "tcp",
    "duration": 0.82
  }
}
```
