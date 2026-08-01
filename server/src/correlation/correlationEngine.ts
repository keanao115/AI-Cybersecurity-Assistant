import { UnifiedSecurityEvent } from '../collectors/collectorTypes.js';
import { memoryDb } from '../db/client.js';
import { getLiveNetworkFlows, NetworkFlowRecord } from '../services/networkFlowService.js';

export interface CorrelatedEvidenceGroup {
  ipAddress: string;
  totalEvents: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  telemetrySources: string[];
  unifiedEvents: UnifiedSecurityEvent[];
  networkFlows: NetworkFlowRecord[];
  firstObservedAt: string;
  lastObservedAt: string;
}

export class CorrelationEngine {
  public static correlateByIp(targetIp?: string): CorrelatedEvidenceGroup[] {
    const events = memoryDb.unifiedEvents;
    const flows = getLiveNetworkFlows();

    const ipMap = new Map<string, { events: UnifiedSecurityEvent[]; flows: NetworkFlowRecord[] }>();

    events.forEach((evt) => {
      const ip = evt.ip || evt.host;
      if (!ip) return;
      if (!ipMap.has(ip)) ipMap.set(ip, { events: [], flows: [] });
      ipMap.get(ip)!.events.push(evt);
    });

    flows.forEach((flow) => {
      const ip = flow.srcIp;
      if (!ipMap.has(ip)) ipMap.set(ip, { events: [], flows: [] });
      ipMap.get(ip)!.flows.push(flow);
    });

    const groups: CorrelatedEvidenceGroup[] = [];

    for (const [ip, data] of ipMap.entries()) {
      if (targetIp && ip !== targetIp) continue;
      if (data.events.length === 0 && data.flows.length === 0) continue;

      const sources = new Set<string>();
      data.events.forEach((e) => sources.add(e.provenance?.telemetrySource || 'UNKNOWN'));
      data.flows.forEach((f) => sources.add(f.provenance?.telemetrySource || 'NETFLOW_COLLECTOR'));

      let highestSev: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' = 'Info';
      if (data.events.some((e) => e.severity === 'Critical')) highestSev = 'Critical';
      else if (data.events.some((e) => e.severity === 'High')) highestSev = 'High';
      else if (data.events.some((e) => e.severity === 'Medium')) highestSev = 'Medium';
      else if (data.events.some((e) => e.severity === 'Low')) highestSev = 'Low';

      groups.push({
        ipAddress: ip,
        totalEvents: data.events.length + data.flows.length,
        severity: highestSev,
        telemetrySources: Array.from(sources),
        unifiedEvents: data.events,
        networkFlows: data.flows,
        firstObservedAt: data.events[0]?.timestamp || data.flows[0]?.timestamp || new Date().toISOString(),
        lastObservedAt: new Date().toISOString(),
      });
    }

    return groups.sort((a, b) => b.totalEvents - a.totalEvents);
  }
}
