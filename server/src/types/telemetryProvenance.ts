import { PlatformMode } from './platformMode.js';

export type TelemetrySource =
  | 'SYNTHETIC_DEMO'
  | 'SEEDED_DEMO'
  | 'NETFLOW_COLLECTOR'
  | 'SYSLOG_COLLECTOR'
  | 'WEF_COLLECTOR'
  | 'PCAP_UPLOAD'
  | 'PCAP_REPLAY'
  | 'SURICATA_EVE'
  | 'ZEEK_LOG'
  | 'NMAP_IMPORT'
  | 'API_INGEST'
  | 'MANUAL_ENTRY'
  | 'THREAT_INTELLIGENCE'
  | 'UNKNOWN';

export type CollectionMethod =
  | 'LIVE_CAPTURE'
  | 'NETWORK_RECEIVER'
  | 'FILE_UPLOAD'
  | 'FILE_IMPORT'
  | 'FILE_REPLAY'
  | 'API'
  | 'MANUAL'
  | 'SIMULATION'
  | 'SEED';

export interface TelemetryProvenance {
  platformMode: PlatformMode;
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
