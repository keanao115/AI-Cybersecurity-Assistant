# Unified Telemetry Schema Specification

## Schema Design

All telemetry sources (Syslog, WEF, NetFlow, PCAP, Zeek, Suricata, Nmap, API) converge into the `UnifiedSecurityEvent` schema:

```typescript
export interface UnifiedSecurityEvent {
  id: string;                      // UUID v4
  timestamp: string;               // ISO-8601 UTC
  collector: CollectorType;        // 'syslog' | 'wef' | 'netflow'
  vendor: string;                  // e.g. 'Zeek', 'Suricata', 'Cisco', 'Microsoft'
  product: string;                 // e.g. 'Zeek-conn.log', 'Suricata IDS', 'Sysmon'
  host: string;                    // Reporting hostname or IP
  ip: string;                      // Source IP
  severity: EventSeverity;         // 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  event_type: string;              // e.g. 'SURICATA_ALERT', 'ZEEK_CONN', 'AUTHENTICATION_FAILURE'
  category: string;                // e.g. 'Network', 'Identity', 'Execution'
  raw: string;                     // Original raw log string or JSON payload
  normalized: Record<string, any>; // Structured fields
  metadata: {
    ingestTimestamp: string;
    protocol: 'UDP' | 'TCP' | 'HTTP';
    sourcePort: number;
    destinationPort: number;
    tags: string[];
  };
  provenance?: TelemetryProvenance;
}
```
