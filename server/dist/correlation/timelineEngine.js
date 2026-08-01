import { memoryDb } from '../db/client.js';
import { getLiveNetworkFlows } from '../services/networkFlowService.js';
export class TimelineEngine {
    static getChronologicalTimeline(targetIp) {
        const items = [];
        memoryDb.unifiedEvents.forEach((e) => {
            if (targetIp && e.ip !== targetIp && e.host !== targetIp)
                return;
            items.push({
                id: e.id,
                timestamp: e.timestamp,
                source: e.provenance?.telemetrySource || e.collector.toUpperCase(),
                eventType: e.event_type,
                summary: e.normalized.summary || `${e.vendor} ${e.product} ${e.event_type}`,
                severity: e.severity,
                host: e.host || e.ip,
                provenance: e.provenance,
            });
        });
        getLiveNetworkFlows().forEach((f) => {
            if (targetIp && f.srcIp !== targetIp && f.destIp !== targetIp)
                return;
            items.push({
                id: f.id,
                timestamp: f.timestamp,
                source: f.provenance?.telemetrySource || 'NETFLOW_COLLECTOR',
                eventType: 'FLOW_RECORD',
                summary: `${f.protocol} ${f.srcIp}:${f.srcPort} -> ${f.destIp}:${f.destPort} (${f.bytes} bytes)`,
                severity: f.anomalyFlag ? 'High' : 'Info',
                host: f.srcIp,
                provenance: f.provenance,
            });
        });
        return items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }
}
