import { FlowCache } from './flowCache.js';
import { ingestNetFlowRecord } from '../services/networkFlowService.js';
import { createProvenance } from '../provenance/provenanceFactory.js';
export class FlowEngine {
    static instance = null;
    cache = new FlowCache();
    static getInstance() {
        if (!FlowEngine.instance) {
            FlowEngine.instance = new FlowEngine();
        }
        return FlowEngine.instance;
    }
    processPacket(packet) {
        const flowKey = `${packet.srcIp}:${packet.srcPort}->${packet.destIp}:${packet.destPort}:${packet.protocol}`;
        let flow = this.cache.get(flowKey);
        if (flow) {
            flow.bytes += packet.frameLength;
            flow.packets += 1;
            flow.durationMs += 10;
            if (packet.flags)
                flow.flags = `${flow.flags || ''}-${packet.flags}`;
        }
        else {
            const isInternalSrc = packet.srcIp.startsWith('192.168.') || packet.srcIp.startsWith('10.');
            const isInternalDst = packet.destIp.startsWith('192.168.') || packet.destIp.startsWith('10.');
            const direction = isInternalSrc && isInternalDst ? 'LATERAL' : isInternalSrc ? 'OUTBOUND' : 'INBOUND';
            const provenance = createProvenance({
                telemetrySource: 'NETFLOW_COLLECTOR',
                collectionMethod: 'LIVE_CAPTURE',
                isSynthetic: false,
                collectorId: 'flow-engine-pcap',
            });
            flow = ingestNetFlowRecord({
                sourceType: 'SPAN_Mirror',
                srcIp: packet.srcIp,
                srcPort: packet.srcPort,
                destIp: packet.destIp,
                destPort: packet.destPort,
                protocol: packet.protocol,
                bytes: packet.frameLength,
                packets: 1,
                durationMs: 10,
                flags: packet.flags || 'SYN',
                direction,
                vlanId: 1,
                geoCountry: isInternalSrc ? 'INTERNAL' : 'EXTERNAL',
                provenance,
            });
            this.cache.put(flowKey, flow);
        }
        return flow;
    }
    getCacheStats() {
        return this.cache.getStats();
    }
}
