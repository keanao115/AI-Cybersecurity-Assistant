# Telemetry Provenance Specification

## Standard Provenance Schema

Every normalized event, network flow, security log, asset, and PCAP session includes the following `provenance` structure:

```typescript
export interface TelemetryProvenance {
  platformMode: 'LIVE' | 'DEMO';
  telemetrySource: TelemetrySource;
  collectionMethod: CollectionMethod;
  isSynthetic: boolean;
  isSeeded: boolean;
  isReplay: boolean;
  collectorId?: string;
  sensorId?: string;
  interfaceName?: string;
  originalFileName?: string;
  ingestionSessionId?: string;
  ingestionTimestamp: string;
  eventTimestamp: string;
  parserName?: string;
  parserVersion?: string;
}
```

---

## Examples

### 1. Live Syslog Telemetry Event
```json
{
  "platformMode": "LIVE",
  "telemetrySource": "SYSLOG_COLLECTOR",
  "collectionMethod": "NETWORK_RECEIVER",
  "isSynthetic": false,
  "isSeeded": false,
  "isReplay": false,
  "collectorId": "syslog-udp-5514",
  "ingestionTimestamp": "2026-08-01T10:15:22.000Z",
  "eventTimestamp": "2026-08-01T10:15:20.000Z",
  "parserName": "LinuxSyslogParser",
  "parserVersion": "3.0.0"
}
```

### 2. Uploaded Binary PCAP Event
```json
{
  "platformMode": "LIVE",
  "telemetrySource": "PCAP_UPLOAD",
  "collectionMethod": "FILE_UPLOAD",
  "isSynthetic": false,
  "isSeeded": false,
  "isReplay": false,
  "originalFileName": "lab-capture.pcap",
  "ingestionSessionId": "PCAP-1722490000000",
  "ingestionTimestamp": "2026-08-01T10:15:22.000Z",
  "eventTimestamp": "2026-07-30T14:04:31.000Z"
}
```

### 3. Synthetic Demonstration Event
```json
{
  "platformMode": "DEMO",
  "telemetrySource": "SYNTHETIC_DEMO",
  "collectionMethod": "SIMULATION",
  "isSynthetic": true,
  "isSeeded": false,
  "isReplay": false,
  "collectorId": "synthetic-engine-flow-generator",
  "ingestionTimestamp": "2026-08-01T10:15:22.000Z",
  "eventTimestamp": "2026-08-01T10:15:22.000Z"
}
```
