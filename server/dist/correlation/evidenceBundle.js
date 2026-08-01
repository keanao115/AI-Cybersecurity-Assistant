import { CorrelationEngine } from './correlationEngine.js';
export class EvidenceBundleService {
    static getEvidenceBundles() {
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
