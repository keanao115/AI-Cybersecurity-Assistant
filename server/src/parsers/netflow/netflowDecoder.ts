// NetFlow v5, NetFlow v9, and IPFIX Binary Buffer Frame Decoder

export interface ParsedNetflowRecord {
  version: 5 | 9 | 10;
  exporterIp: string;
  sequenceNumber: number;
  sourceIp: string;
  destinationIp: string;
  nextHopIp?: string;
  inputInterface: number;
  outputInterface: number;
  packets: number;
  bytes: number;
  firstSwitchedMs: number;
  lastSwitchedMs: number;
  durationMs: number;
  sourcePort: number;
  destinationPort: number;
  protocolNumber: number;
  protocol: string;
  tcpFlags?: number;
  tos?: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
}

const PROTOCOL_NAMES: Record<number, string> = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  89: 'OSPF',
  132: 'SCTP',
};

export function decodeNetflowBuffer(buffer: Buffer, exporterIp: string): ParsedNetflowRecord[] {
  if (!buffer || buffer.length < 24) return [];

  const version = buffer.readUInt16BE(0);

  if (version === 5) {
    return decodeNetflowV5(buffer, exporterIp);
  } else if (version === 9 || version === 10) { // 10 is IPFIX
    return decodeNetflowV9OrIpfix(buffer, exporterIp, version as 9 | 10);
  }

  return [];
}

// ─── NetFlow v5 Decoder ───────────────────────────────────────────────────────
function decodeNetflowV5(buffer: Buffer, exporterIp: string): ParsedNetflowRecord[] {
  const count = buffer.readUInt16BE(2);
  const sysUptime = buffer.readUInt32BE(4);
  const unixSecs = buffer.readUInt32BE(8);
  const sequenceNumber = buffer.readUInt32BE(16);

  const records: ParsedNetflowRecord[] = [];
  const headerLen = 24;
  const recordLen = 48;

  for (let i = 0; i < count; i++) {
    const offset = headerLen + i * recordLen;
    if (offset + recordLen > buffer.length) break;

    const srcIp = parseIpv4(buffer, offset);
    const dstIp = parseIpv4(buffer, offset + 4);
    const nextHop = parseIpv4(buffer, offset + 8);
    const inputIf = buffer.readUInt16BE(offset + 12);
    const outputIf = buffer.readUInt16BE(offset + 14);
    const pkts = buffer.readUInt32BE(offset + 16);
    const bytes = buffer.readUInt32BE(offset + 20);
    const first = buffer.readUInt32BE(offset + 24);
    const last = buffer.readUInt32BE(offset + 28);
    const srcPort = buffer.readUInt16BE(offset + 32);
    const dstPort = buffer.readUInt16BE(offset + 34);
    const tcpFlags = buffer.readUInt8(offset + 37);
    const protoNum = buffer.readUInt8(offset + 38);
    const tos = buffer.readUInt8(offset + 39);

    const durationMs = Math.max(0, last - first);
    const protocol = PROTOCOL_NAMES[protoNum] || `PROTO-${protoNum}`;

    // Threat heuristic for suspicious traffic
    let severity: ParsedNetflowRecord['severity'] = 'Info';
    if (bytes > 100 * 1024 * 1024) severity = 'High'; // >100MB flow
    else if (dstPort === 4444 || dstPort === 8443 || dstPort === 6667) severity = 'High'; // Suspicious C2 ports

    records.push({
      version: 5,
      exporterIp,
      sequenceNumber,
      sourceIp: srcIp,
      destinationIp: dstIp,
      nextHopIp: nextHop,
      inputInterface: inputIf,
      outputInterface: outputIf,
      packets: pkts,
      bytes,
      firstSwitchedMs: first,
      lastSwitchedMs: last,
      durationMs,
      sourcePort: srcPort,
      destinationPort: dstPort,
      protocolNumber: protoNum,
      protocol,
      tcpFlags,
      tos,
      severity,
    });
  }

  return records;
}

// ─── NetFlow v9 & IPFIX Decoder ───────────────────────────────────────────────
function decodeNetflowV9OrIpfix(buffer: Buffer, exporterIp: string, version: 9 | 10): ParsedNetflowRecord[] {
  const count = buffer.readUInt16BE(2);
  const sequenceNumber = buffer.readUInt32BE(12);

  // Simplified v9 / IPFIX frame parser reading data flow sets
  const records: ParsedNetflowRecord[] = [];
  const headerLen = version === 10 ? 16 : 20;

  if (buffer.length <= headerLen) return [];

  let offset = headerLen;
  while (offset + 4 <= buffer.length) {
    const flowSetId = buffer.readUInt16BE(offset);
    const flowSetLength = buffer.readUInt16BE(offset + 2);

    if (flowSetLength < 4 || offset + flowSetLength > buffer.length) break;

    // Data FlowSet (ID > 255)
    if (flowSetId > 255) {
      // Decode standard binary fields if offset permits
      let recordOffset = offset + 4;
      while (recordOffset + 24 <= offset + flowSetLength) {
        const srcIp = parseIpv4(buffer, recordOffset);
        const dstIp = parseIpv4(buffer, recordOffset + 4);
        const pkts = buffer.readUInt32BE(recordOffset + 8);
        const bytes = buffer.readUInt32BE(recordOffset + 12);
        const srcPort = buffer.readUInt16BE(recordOffset + 16);
        const dstPort = buffer.readUInt16BE(recordOffset + 18);
        const protoNum = buffer.readUInt8(recordOffset + 20);

        const protocol = PROTOCOL_NAMES[protoNum] || `PROTO-${protoNum}`;

        records.push({
          version,
          exporterIp,
          sequenceNumber,
          sourceIp: srcIp,
          destinationIp: dstIp,
          inputInterface: 1,
          outputInterface: 2,
          packets: pkts || 1,
          bytes: bytes || 64,
          firstSwitchedMs: Date.now(),
          lastSwitchedMs: Date.now(),
          durationMs: 0,
          sourcePort: srcPort,
          destinationPort: dstPort,
          protocolNumber: protoNum,
          protocol,
          severity: 'Info',
        });

        recordOffset += 24;
      }
    }

    offset += flowSetLength;
  }

  return records;
}

function parseIpv4(buffer: Buffer, offset: number): string {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}
