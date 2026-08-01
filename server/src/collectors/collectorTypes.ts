// Production-Grade Enterprise SOC Telemetry Collector Types & Models

export type CollectorState =
  | 'Initializing'
  | 'Running'
  | 'Paused'
  | 'Stopping'
  | 'Stopped'
  | 'Failed'
  | 'Restarting'
  | 'Degraded';

export type CollectorType = 'syslog' | 'wef' | 'netflow';

export type EventSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface UnifiedSecurityEvent {
  id: string;                      // UUID v4
  timestamp: string;               // ISO-8601 UTC timestamp
  collector: CollectorType;
  vendor: string;                  // e.g. 'Cisco', 'PaloAlto', 'Microsoft', 'Linux', 'Generic'
  product: string;                 // e.g. 'ASA', 'PAN-OS', 'Sysmon', 'sshd', 'NetFlow-v9'
  host: string;                    // Hostname or FQDN
  ip: string;                      // Source IP of the reporting device or exporter
  severity: EventSeverity;
  event_type: string;              // e.g. 'AUTHENTICATION_FAILURE', 'PROCESS_CREATION', 'FLOW_RECORD'
  category: string;                // e.g. 'Identity', 'Execution', 'Network', 'Audit'
  raw: string;                     // Original raw log string or hex payload preserved (sanitized)
  normalized: Record<string, any>; // Structured key-value fields specific to event type
  metadata: {
    ingestTimestamp: string;
    protocol: 'UDP' | 'TCP' | 'HTTP';
    sourcePort: number;
    destinationPort: number;
    facility?: string;
    eventId?: string;
    bytes?: number;
    packets?: number;
    durationMs?: number;
    tags: string[];
  };
  provenance?: import('../types/telemetryProvenance.js').TelemetryProvenance;
}

export interface CollectorHealth {
  name: string;
  type: CollectorType;
  state: CollectorState;
  liveness: boolean;
  readiness: boolean;
  uptimeSeconds: number;
  lastEventTimestamp: string | null;
  listeningPorts: number[];
  activeConnections: number;
  healthMessage: string;
}

export interface CollectorMetrics {
  name: string;
  type: CollectorType;
  state: CollectorState;
  eventsProcessedTotal: number;
  eventsPerSecond: number;
  bytesProcessedTotal: number;
  droppedPacketsTotal: number;
  droppedReasonBreakdown: {
    rateLimited: number;
    backpressureEvicted: number;
    malformed: number;
    paused: number;
  };
  parserErrorTotal: number;
  piiMaskedTotal: number;
  averageLatencyMs: number;
  queueDepth: number;
  queueMaxCapacity: number;
  watermarkStatus: 'NORMAL' | 'LOW_WATERMARK' | 'HIGH_WATERMARK' | 'CRITICAL_WATERMARK';
  activeSourceIpsCount: number;
}

export interface CollectorConfig {
  name: string;
  type: CollectorType;
  enabled: boolean;
  udpPort?: number;
  tcpPort?: number;
  httpPort?: number;
  maxPacketSizeBytes: number;
  rateLimitEventsPerSec: number;
  rateLimitBurst: number;
  enableTls: boolean;
  enablePiiMasking: boolean;
  enabledVendorParsers: string[];
}
