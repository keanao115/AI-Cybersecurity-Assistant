# Operating Modes Guide: LIVE vs DEMO

## Overview

The platform supports two distinct operating modes:
1. **LIVE MODE** (Default)
2. **DEMO MODE**

The operating mode is configured via environment variables or central configuration.

---

## 1. LIVE MODE (Default Production Mode)

### Configuration
```env
PLATFORM_MODE=LIVE
ENABLE_SYNTHETIC_DATA=false
ENABLE_SEED_DATA=false
ENABLE_ATTACK_SIMULATION=false
ALLOW_RUNTIME_MODE_SWITCH=false
```

### Behavior
- **Synthetic Data**: **DISABLED**. `SyntheticFlowGenerator` is blocked from running.
- **Seeded Assets**: **DISABLED**. `memoryDb` and PostgreSQL start empty.
- **Data Ingestion**: Accepts genuine incoming events from Syslog (UDP 5514 / TCP 5515), WEF (HTTP 5516), NetFlow (UDP 2055), and PCAP uploads.
- **UI State**: Displays a glowing green `LIVE MODE` badge in the header. Empty dashboards display an honest empty state ("No live telemetry received").

---

## 2. DEMO MODE (Controlled Demonstration Environment)

### Configuration
```env
PLATFORM_MODE=DEMO
ENABLE_SYNTHETIC_DATA=true
ENABLE_SEED_DATA=true
ENABLE_ATTACK_SIMULATION=true
ALLOW_RUNTIME_MODE_SWITCH=true
```

### Behavior
- **Synthetic Data**: **ENABLED**. `SyntheticFlowGenerator` runs every 8 seconds, creating simulated flow records tagged with `isSynthetic = true` and `telemetrySource = 'SYNTHETIC_DEMO'`.
- **Seeded Assets**: **ENABLED**. Seeded demonstration assets are loaded into the inventory, tagged with `isSeeded = true` and `telemetrySource = 'SEEDED_DEMO'`.
- **UI State**: Displays an amber `DEMO MODE` badge in the header and a persistent warning banner across all screens ("CONTROLLED DEMONSTRATION ENVIRONMENT: Events must not be treated as evidence of actual compromise").
