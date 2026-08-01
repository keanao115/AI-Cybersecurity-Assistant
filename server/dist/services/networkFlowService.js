import { query } from '../db/client.js';
import { createLiveCollectorProvenance } from '../provenance/provenanceFactory.js';
import { loadPlatformConfig } from '../config/platformConfig.js';
// Start empty by default so LIVE mode returns genuine empty dataset
const activeFlowStream = [];
export function detectFlowAnomalies(flow) {
    let anomalyFlag = false;
    let anomalyReason = '';
    let riskScore = 0;
    // Rule 1: High outbound data volume (>5MB in single flow)
    if (flow.direction === 'OUTBOUND' && flow.bytes > 5 * 1024 * 1024) {
        anomalyFlag = true;
        anomalyReason = `Potential Data Exfiltration: Large outbound transfer of ${(flow.bytes / (1024 * 1024)).toFixed(1)}MB to ${flow.destIp}`;
        riskScore += 65;
    }
    // Rule 2: Suspicious ports (e.g. 4444, 6667, 31337)
    const suspiciousPorts = [4444, 5555, 6667, 31337, 1337];
    if (suspiciousPorts.includes(flow.destPort) || suspiciousPorts.includes(flow.srcPort)) {
        anomalyFlag = true;
        anomalyReason = `Reverse Shell / C2 Port Activity: Flow uses suspicious port ${flow.destPort}`;
        riskScore += 80;
    }
    // Rule 3: Internal lateral SMB/RDP spike from non-DC
    if (flow.direction === 'LATERAL' && (flow.destPort === 445 || flow.destPort === 3389) && !flow.srcIp.endsWith('.10')) {
        riskScore += 35;
        if (flow.packets > 100) {
            anomalyFlag = true;
            anomalyReason = `Lateral Movement Spike: High volume ${flow.destPort === 445 ? 'SMB' : 'RDP'} traffic to ${flow.destIp}`;
            riskScore += 30;
        }
    }
    return {
        anomalyFlag,
        anomalyReason: anomalyReason || undefined,
        riskScore: Math.min(100, riskScore)
    };
}
export function getLiveNetworkFlows(filters) {
    const config = loadPlatformConfig();
    const allowSynthetic = filters?.includeSynthetic ?? (config.platformMode === 'DEMO' && config.enableSyntheticData);
    let result = [...activeFlowStream];
    // In LIVE mode, filter out any synthetic records
    if (!allowSynthetic) {
        result = result.filter((f) => !f.provenance?.isSynthetic);
    }
    if (filters?.protocol && filters.protocol !== 'ALL') {
        result = result.filter(f => f.protocol.toUpperCase() === filters.protocol?.toUpperCase());
    }
    if (filters?.anomalyOnly) {
        result = result.filter(f => f.anomalyFlag);
    }
    if (filters?.direction && filters.direction !== 'ALL') {
        result = result.filter(f => f.direction === filters.direction);
    }
    return result;
}
export function ingestNetFlowRecord(record) {
    const anomalyInfo = detectFlowAnomalies(record);
    const provenance = record.provenance || createLiveCollectorProvenance('netflow', 'netflow-udp-2055');
    const newRecord = {
        ...record,
        id: record.provenance?.isSynthetic ? `demo-flow-${Date.now()}-${Math.floor(Math.random() * 1000)}` : `FLOW-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        timestamp: new Date().toISOString(),
        anomalyFlag: anomalyInfo.anomalyFlag,
        anomalyReason: anomalyInfo.anomalyReason,
        riskScore: anomalyInfo.riskScore,
        provenance,
    };
    activeFlowStream.unshift(newRecord);
    if (activeFlowStream.length > 500)
        activeFlowStream.pop();
    // Async DB insert with provenance columns
    query(`INSERT INTO network_flows (id, timestamp, source_type, src_ip, src_port, dest_ip, dest_port, protocol, bytes, packets, duration_ms, flags, direction, vlan_id, geo_country, anomaly_flag, risk_score, platform_mode, telemetry_source, collection_method, is_synthetic)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`, [
        newRecord.id,
        newRecord.timestamp,
        newRecord.sourceType,
        newRecord.srcIp,
        newRecord.srcPort,
        newRecord.destIp,
        newRecord.destPort,
        newRecord.protocol,
        newRecord.bytes,
        newRecord.packets,
        newRecord.durationMs,
        newRecord.flags || '',
        newRecord.direction,
        newRecord.vlanId,
        newRecord.geoCountry,
        newRecord.anomalyFlag,
        newRecord.riskScore,
        provenance.platformMode,
        provenance.telemetrySource,
        provenance.collectionMethod,
        provenance.isSynthetic,
    ]).catch(() => { });
    return newRecord;
}
export function getTopTalkers() {
    const flows = getLiveNetworkFlows();
    const ipMap = new Map();
    let total = 0;
    flows.forEach(f => {
        ipMap.set(f.srcIp, (ipMap.get(f.srcIp) || 0) + f.bytes);
        total += f.bytes;
    });
    const sorted = Array.from(ipMap.entries())
        .map(([ip, bytes]) => ({ ip, bytes, percentage: total > 0 ? parseFloat(((bytes / total) * 100).toFixed(1)) : 0 }))
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 5);
    return sorted;
}
export function calculateNetworkBandwidthMetrics() {
    const flows = getLiveNetworkFlows();
    const totalBytes = flows.reduce((acc, f) => acc + f.bytes, 0);
    const totalPackets = flows.reduce((acc, f) => acc + f.packets, 0);
    const anomalyCount = flows.filter(f => f.anomalyFlag).length;
    return {
        activeFlowCount: flows.length,
        totalMbps: ((totalBytes * 8) / (1024 * 1024)).toFixed(2),
        packetsPerSec: Math.round(totalPackets / 10),
        anomalyCount,
        topTalkers: getTopTalkers()
    };
}
// NOTE: Automatic synthetic generation loop was removed.
// Synthetic data runs ONLY via SyntheticFlowGenerator when PLATFORM_MODE=DEMO and ENABLE_SYNTHETIC_DATA=true.
