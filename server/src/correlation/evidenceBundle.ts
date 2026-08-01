import { UnifiedSecurityEvent } from '../collectors/collectorTypes.js';
import { NetworkFlowRecord } from '../services/networkFlowService.js';
import { CorrelationEngine, CorrelatedEvidenceGroup } from './correlationEngine.js';

export interface EvidenceBundle {
  bundleId: string;
  targetIp: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  createdAt: string;
  telemetrySources: string[];
  unifiedEvents: UnifiedSecurityEvent[];
  networkFlows: NetworkFlowRecord[];
  evidenceCount: number;
  mitreTechniques: string[];
}

export class EvidenceBundleService {
  public static getEvidenceBundles(): EvidenceBundle[] {
    const groups = CorrelationEngine.correlateByIp();
    return groups.map((g, idx) => ({
      bundleId: `BUNDLE-${1000 + idx}`,
      targetIp: g.ipAddress,
      title: `Multi-Source Incident Evidence Bundle (${g.ipAddress})`,
      severity: g.severity,
      createdAt: g.lastObservedAt,
      telemetrySources: g.telemetrySources,
      unifiedEvents: g.unifiedEvents,
      networkFlows: g.networkFlows,
      evidenceCount: g.totalEvents,
      mitreTechniques: ['T1071.001 (Web Protocols)', 'T1021.002 (SMB/Windows Admin Shares)', 'T1110 (Brute Force)'],
    }));
  }
}
