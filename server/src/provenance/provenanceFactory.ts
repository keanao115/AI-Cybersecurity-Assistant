import { TelemetryProvenance, TelemetrySource, CollectionMethod } from '../types/telemetryProvenance.js';
import { loadPlatformConfig } from '../config/platformConfig.js';

export function createProvenance(options: {
  telemetrySource: TelemetrySource;
  collectionMethod: CollectionMethod;
  isSynthetic?: boolean;
  isSeeded?: boolean;
  isReplay?: boolean;
  collectorId?: string;
  sensorId?: string;
  interfaceName?: string;
  originalFileName?: string;
  ingestionSessionId?: string;
  eventTimestamp?: string;
  parserName?: string;
  parserVersion?: string;
}): TelemetryProvenance {
  const config = loadPlatformConfig();
  const now = new Date().toISOString();

  return {
    platformMode: config.platformMode,
    telemetrySource: options.telemetrySource,
    collectionMethod: options.collectionMethod,
    isSynthetic: options.isSynthetic ?? (options.telemetrySource === 'SYNTHETIC_DEMO'),
    isSeeded: options.isSeeded ?? (options.telemetrySource === 'SEEDED_DEMO'),
    isReplay: options.isReplay ?? (options.telemetrySource === 'PCAP_REPLAY'),
    collectorId: options.collectorId,
    sensorId: options.sensorId,
    interfaceName: options.interfaceName,
    originalFileName: options.originalFileName,
    ingestionSessionId: options.ingestionSessionId,
    ingestionTimestamp: now,
    eventTimestamp: options.eventTimestamp || now,
    parserName: options.parserName,
    parserVersion: options.parserVersion || '3.0.0',
  };
}

export function createLiveCollectorProvenance(
  collectorType: 'syslog' | 'wef' | 'netflow',
  collectorId: string,
  eventTimestamp?: string
): TelemetryProvenance {
  const sourceMap: Record<string, TelemetrySource> = {
    syslog: 'SYSLOG_COLLECTOR',
    wef: 'WEF_COLLECTOR',
    netflow: 'NETFLOW_COLLECTOR',
  };

  return createProvenance({
    telemetrySource: sourceMap[collectorType] || 'UNKNOWN',
    collectionMethod: 'NETWORK_RECEIVER',
    isSynthetic: false,
    isSeeded: false,
    isReplay: false,
    collectorId,
    eventTimestamp,
  });
}

export function createSyntheticDemoProvenance(scenarioId: string = 'generic-demo'): TelemetryProvenance {
  return createProvenance({
    telemetrySource: 'SYNTHETIC_DEMO',
    collectionMethod: 'SIMULATION',
    isSynthetic: true,
    isSeeded: false,
    isReplay: false,
    collectorId: `synthetic-engine-${scenarioId}`,
  });
}

export function createSeededDemoProvenance(seedCategory: string = 'sample-asset'): TelemetryProvenance {
  return createProvenance({
    telemetrySource: 'SEEDED_DEMO',
    collectionMethod: 'SEED',
    isSynthetic: false,
    isSeeded: true,
    isReplay: false,
    collectorId: `seed-loader-${seedCategory}`,
  });
}

export function createPcapUploadProvenance(fileName: string, sessionId: string): TelemetryProvenance {
  return createProvenance({
    telemetrySource: 'PCAP_UPLOAD',
    collectionMethod: 'FILE_UPLOAD',
    isSynthetic: false,
    isSeeded: false,
    isReplay: false,
    originalFileName: fileName,
    ingestionSessionId: sessionId,
  });
}
