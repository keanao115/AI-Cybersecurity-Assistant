import { query } from '../db/client.js';
import { broadcastTelemetryEvent } from './websocketService.js';

export interface NetworkFlowRecord {
  id: string;
  timestamp: string;
  sourceType: 'NetFlow_v9' | 'IPFIX' | 'sFlow' | 'SPAN_Mirror';
  srcIp: string;
  srcPort: number;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'OTHER';
  bytes: number;
  packets: number;
  durationMs: number;
  flags?: string;
  direction: 'INBOUND' | 'OUTBOUND' | 'LATERAL';
  vlanId: number;
  geoCountry: string;
  anomalyFlag: boolean;
  anomalyReason?: string;
  riskScore: number;
}

const activeFlowStream: NetworkFlowRecord[] = [
  {
    id: 'FLOW-101',
    timestamp: new Date(Date.now() - 5000).toISOString(),
    sourceType: 'NetFlow_v9',
    srcIp: '192.168.1.105',
    srcPort: 54320,
    destIp: '192.168.1.10',
    destPort: 445,
    protocol: 'TCP',
    bytes: 14200,
    packets: 28,
    durationMs: 820,
    flags: 'SYN-ACK',
    direction: 'LATERAL',
    vlanId: 10,
    geoCountry: 'INTERNAL',
    anomalyFlag: false,
    riskScore: 10
  },
  {
    id: 'FLOW-102',
    timestamp: new Date(Date.now() - 2000).toISOString(),
    sourceType: 'SPAN_Mirror',
    srcIp: '192.168.1.50',
    srcPort: 443,
    destIp: '192.168.1.120',
    destPort: 58912,
    protocol: 'TCP',
    bytes: 1048576,
    packets: 820,
    durationMs: 4200,
    flags: 'ACK-PUSH',
    direction: 'INBOUND',
    vlanId: 20,
    geoCountry: 'INTERNAL',
    anomalyFlag: false,
    riskScore: 5
  },
  {
    id: 'FLOW-103',
    timestamp: new Date().toISOString(),
    sourceType: 'IPFIX',
    srcIp: '185.220.101.5',
    srcPort: 4444,
    destIp: '192.168.1.105',
    destPort: 49152,
    protocol: 'TCP',
    bytes: 512,
    packets: 4,
    durationMs: 120,
    flags: 'SYN',
    direction: 'INBOUND',
    vlanId: 1,
    geoCountry: 'RU',
    anomalyFlag: true,
    anomalyReason: 'High-risk external C2 IP connection on non-standard port 4444',
    riskScore: 90
  }
];

export function detectFlowAnomalies(flow: Omit<NetworkFlowRecord, 'id' | 'timestamp' | 'anomalyFlag' | 'riskScore'>): { anomalyFlag: boolean; anomalyReason?: string; riskScore: number } {
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

export function getLiveNetworkFlows(filters?: { protocol?: string; anomalyOnly?: boolean; direction?: string }): NetworkFlowRecord[] {
  let result = activeFlowStream;
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

export function ingestNetFlowRecord(record: Omit<NetworkFlowRecord, 'id' | 'timestamp' | 'anomalyFlag' | 'riskScore'>): NetworkFlowRecord {
  const anomalyInfo = detectFlowAnomalies(record);

  const newRecord: NetworkFlowRecord = {
    ...record,
    id: `FLOW-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    timestamp: new Date().toISOString(),
    anomalyFlag: anomalyInfo.anomalyFlag,
    anomalyReason: anomalyInfo.anomalyReason,
    riskScore: anomalyInfo.riskScore
  };

  activeFlowStream.unshift(newRecord);
  if (activeFlowStream.length > 500) activeFlowStream.pop();

  // Async DB insert (fails silently to memory fallback)
  query(
    `INSERT INTO network_flows (id, timestamp, source_type, src_ip, src_port, dest_ip, dest_port, protocol, bytes, packets, duration_ms, flags, direction, vlan_id, geo_country, anomaly_flag, risk_score)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
    [newRecord.id, newRecord.timestamp, newRecord.sourceType, newRecord.srcIp, newRecord.srcPort, newRecord.destIp, newRecord.destPort, newRecord.protocol, newRecord.bytes, newRecord.packets, newRecord.durationMs, newRecord.flags || '', newRecord.direction, newRecord.vlanId, newRecord.geoCountry, newRecord.anomalyFlag, newRecord.riskScore]
  ).catch(() => {});

  return newRecord;
}

export function getTopTalkers(): Array<{ ip: string; bytes: number; percentage: number }> {
  const ipMap = new Map<string, number>();
  let total = 0;

  activeFlowStream.forEach(f => {
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
  const totalBytes = activeFlowStream.reduce((acc, f) => acc + f.bytes, 0);
  const totalPackets = activeFlowStream.reduce((acc, f) => acc + f.packets, 0);
  const anomalyCount = activeFlowStream.filter(f => f.anomalyFlag).length;

  return {
    activeFlowCount: activeFlowStream.length,
    totalMbps: ((totalBytes * 8) / (1024 * 1024)).toFixed(2),
    packetsPerSec: Math.round(totalPackets / 10),
    anomalyCount,
    topTalkers: getTopTalkers()
  };
}

// Backend Synthetic NetFlow Generation Loop (Every 8 Seconds)
let generatorInterval: NodeJS.Timeout | null = null;

export function startSyntheticFlowGenerator() {
  if (generatorInterval) return;

  const sampleSrcIps = ['192.168.1.105', '192.168.1.50', '192.168.1.120', '10.0.4.15', '185.220.101.5', '192.168.1.10'];
  const sampleDstIps = ['192.168.1.10', '8.8.8.8', '1.1.1.1', '192.168.1.50', '104.21.55.2'];
  const protocols: Array<'TCP' | 'UDP' | 'ICMP'> = ['TCP', 'TCP', 'TCP', 'UDP', 'ICMP'];
  const sources: Array<'NetFlow_v9' | 'IPFIX' | 'sFlow' | 'SPAN_Mirror'> = ['NetFlow_v9', 'IPFIX', 'sFlow', 'SPAN_Mirror'];

  generatorInterval = setInterval(() => {
    const srcIp = sampleSrcIps[Math.floor(Math.random() * sampleSrcIps.length)];
    const destIp = sampleDstIps[Math.floor(Math.random() * sampleDstIps.length)];
    const isInternalSrc = srcIp.startsWith('192.168.') || srcIp.startsWith('10.');
    const isInternalDst = destIp.startsWith('192.168.') || destIp.startsWith('10.');

    const direction: 'INBOUND' | 'OUTBOUND' | 'LATERAL' = isInternalSrc && isInternalDst ? 'LATERAL' : isInternalSrc ? 'OUTBOUND' : 'INBOUND';
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];

    const record = ingestNetFlowRecord({
      sourceType: sources[Math.floor(Math.random() * sources.length)],
      srcIp,
      srcPort: Math.floor(Math.random() * 45000) + 1024,
      destIp,
      destPort: [80, 443, 53, 445, 3389, 4444][Math.floor(Math.random() * 6)],
      protocol,
      bytes: Math.floor(Math.random() * 200000) + 128,
      packets: Math.floor(Math.random() * 150) + 1,
      durationMs: Math.floor(Math.random() * 2000) + 50,
      flags: protocol === 'TCP' ? ['SYN', 'ACK-PUSH', 'SYN-ACK', 'RST'][Math.floor(Math.random() * 4)] : '',
      direction,
      vlanId: isInternalSrc ? 10 : 1,
      geoCountry: isInternalSrc ? 'INTERNAL' : ['US', 'DE', 'RU', 'CN'][Math.floor(Math.random() * 4)]
    });

    broadcastTelemetryEvent({
      type: 'NETFLOW_RECORD',
      record,
      timestamp: new Date().toISOString()
    });
  }, 8000);
}

// Start synthetic loop on load
startSyntheticFlowGenerator();
