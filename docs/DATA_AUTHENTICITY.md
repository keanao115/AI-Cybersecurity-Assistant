# Data Authenticity Architecture & Principles

## Executive Summary

The **Intelligent Enterprise Security Operations Platform** enforces strict data authenticity to guarantee that simulated, seeded, uploaded, imported, and live security telemetry are never mixed together or presented misleadingly.

---

## Non-Negotiable Authenticity Rules

1. **No Synthetic Telemetry in LIVE Mode**: Background flow generators (`Math.random()`) are completely disabled in LIVE mode (`PLATFORM_MODE=LIVE`).
2. **Immutable Telemetry Provenance**: Every security event, flow, alert, pcap session, asset, and log carries immutable provenance metadata (`platformMode`, `telemetrySource`, `collectionMethod`, `isSynthetic`, `isSeeded`, `isReplay`).
3. **Honest Empty States**: When an environment in LIVE mode has received zero live events, dashboards display honest empty state messages rather than fabricating fake activity.
4. **Visual Transparency**: Persistent `LIVE MODE` / `DEMO MODE` badges are rendered on the application shell, and color-coded `TelemetrySourceBadge` tags (`LIVE SYSLOG`, `LIVE WEF`, `LIVE NETFLOW`, `UPLOADED PCAP`, `NMAP IMPORT`, `DEMO SYNTHETIC`, `DEMO SEEDED`) accompany every event.
5. **No Fake Health Status**: Collector health probes report actual runtime state, socket bind status, and event counters.

---

## Telemetry Source Classification

| Telemetry Source | Description | Provenance Category |
|---|---|---|
| `SYSLOG_COLLECTOR` | Received over Syslog UDP (5514) / TCP (5515) | Live Receiver |
| `WEF_COLLECTOR` | Received over Windows Event Forwarding HTTP (5516) | Live Receiver |
| `NETFLOW_COLLECTOR` | Received over NetFlow UDP (2055) binary decoder | Live Receiver |
| `PCAP_UPLOAD` | Extracted from uploaded binary `.pcap` capture file | File Upload |
| `NMAP_IMPORT` | Extracted from uploaded Nmap XML scan file | File Import |
| `API_INGEST` | Sent via authenticated REST `/api/ingest` endpoint | API Ingestion |
| `SYNTHETIC_DEMO` | Controlled background demonstration flow | Demo Simulation |
| `SEEDED_DEMO` | Seeded demonstration asset record | Demo Seed |
