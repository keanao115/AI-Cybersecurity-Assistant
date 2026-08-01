// Real Binary PCAP Parser — Pure JavaScript, zero external dependencies
// Supports: PCAP format (magic 0xa1b2c3d4 LE / 0xd4c3b2a1 BE)
// Decodes: Ethernet II → IPv4 → TCP / UDP / ICMP
// Extracts: DNS queries, HTTP methods/hosts, TLS ClientHello SNI, TCP flow stats
// ─── Utility: Read integers from Buffer ──────────────────────────────────────
function readUint32LE(buf, off) { return buf.readUInt32LE(off); }
function readUint32BE(buf, off) { return buf.readUInt32BE(off); }
function readUint16BE(buf, off) { return buf.readUInt16BE(off); }
function ipFromBytes(buf, off) {
    return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}
// ─── DNS Query Name Parser ────────────────────────────────────────────────────
function parseDnsName(buf, offset) {
    const labels = [];
    let jumped = false;
    let end = offset;
    let safety = 0;
    while (safety++ < 64 && offset < buf.length) {
        const len = buf[offset];
        if (len === 0) {
            if (!jumped)
                end = offset + 1;
            break;
        }
        if ((len & 0xc0) === 0xc0) {
            // DNS pointer
            if (!jumped)
                end = offset + 2;
            const ptr = ((len & 0x3f) << 8) | buf[offset + 1];
            offset = ptr;
            jumped = true;
            continue;
        }
        offset++;
        labels.push(buf.slice(offset, offset + len).toString('ascii'));
        offset += len;
        if (!jumped)
            end = offset;
    }
    return { name: labels.join('.'), end };
}
// ─── DNS Record Type Mapping ──────────────────────────────────────────────────
const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 255: 'ANY' };
// ─── DGA Entropy Score ────────────────────────────────────────────────────────
function calculateDgaScore(domain) {
    const label = domain.split('.')[0];
    if (!label || label.length < 4)
        return 0;
    const freqs = {};
    for (const c of label)
        freqs[c] = (freqs[c] || 0) + 1;
    let entropy = 0;
    for (const n of Object.values(freqs)) {
        const p = n / label.length;
        entropy -= p * Math.log2(p);
    }
    return Math.min(10, parseFloat((entropy * 1.4).toFixed(1)));
}
// ─── TCP Flags Decoder ────────────────────────────────────────────────────────
function decodeTcpFlags(flags) {
    const f = [];
    if (flags & 0x01)
        f.push('FIN');
    if (flags & 0x02)
        f.push('SYN');
    if (flags & 0x04)
        f.push('RST');
    if (flags & 0x08)
        f.push('PSH');
    if (flags & 0x10)
        f.push('ACK');
    if (flags & 0x20)
        f.push('URG');
    return f.join('|') || 'NONE';
}
// ─── TLS Cipher Suite Names ────────────────────────────────────────────────────
const TLS_VERSIONS = {
    0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
};
// ─── Main PCAP Parser ─────────────────────────────────────────────────────────
export function parsePcapBuffer(buffer) {
    const result = {
        isValid: false, linkType: 1, totalPackets: 0, validPackets: 0,
        captureDurationSec: 0, protocolCounts: {},
        dnsRecords: [], httpRecords: [], tlsRecords: [], tcpFlows: [], flaggedThreats: [],
    };
    if (buffer.length < 24) {
        return { ...result, error: 'Buffer too small for PCAP global header (< 24 bytes)' };
    }
    // ── Global Header ────────────────────────────────────────────────────────────
    const magic = buffer.readUInt32LE(0);
    const isLE = magic === 0xd4c3b2a1 || magic === 0xa1b23c4d;
    const isBE = magic === 0xa1b2c3d4 || magic === 0x4d3cb2a1;
    if (!isLE && !isBE) {
        return { ...result, error: `Invalid PCAP magic: 0x${magic.toString(16)}. Not a PCAP file.` };
    }
    const readU32 = isLE ? readUint32LE : readUint32BE;
    result.isValid = true;
    result.linkType = isLE ? buffer.readUInt16LE(20) : buffer.readUInt16BE(20);
    const tcpFlowMap = new Map();
    let offset = 24;
    let firstTs = 0;
    let lastTs = 0;
    // ── Parse Packets ─────────────────────────────────────────────────────────────
    while (offset + 16 <= buffer.length) {
        const tsSec = readU32(buffer, offset);
        const tsUsec = readU32(buffer, offset + 4);
        const inclLen = readU32(buffer, offset + 8);
        // const origLen = readU32(buffer, offset + 12); // unused but valid
        offset += 16;
        if (inclLen > 65535 || offset + inclLen > buffer.length)
            break;
        result.totalPackets++;
        if (firstTs === 0)
            firstTs = tsSec;
        lastTs = tsSec;
        const pktBuf = buffer.slice(offset, offset + inclLen);
        offset += inclLen;
        // ── Ethernet II (link type 1) ────────────────────────────────────────────
        if (result.linkType !== 1 || pktBuf.length < 14) {
            result.protocolCounts['OTHER'] = (result.protocolCounts['OTHER'] || 0) + 1;
            continue;
        }
        const ethertype = readUint16BE(pktBuf, 12);
        if (ethertype !== 0x0800) { // Only IPv4
            result.protocolCounts['NON-IPv4'] = (result.protocolCounts['NON-IPv4'] || 0) + 1;
            continue;
        }
        // ── IPv4 Header ───────────────────────────────────────────────────────────
        if (pktBuf.length < 34)
            continue;
        const ipStart = 14;
        const ihl = (pktBuf[ipStart] & 0x0f) * 4;
        const proto = pktBuf[ipStart + 9];
        const srcIp = ipFromBytes(pktBuf, ipStart + 12);
        const dstIp = ipFromBytes(pktBuf, ipStart + 16);
        const tsStr = new Date(tsSec * 1000).toISOString();
        let protoName = 'OTHER';
        // ── TCP (proto 6) ─────────────────────────────────────────────────────────
        if (proto === 6 && pktBuf.length >= ipStart + ihl + 20) {
            protoName = 'TCP';
            const tcpStart = ipStart + ihl;
            const srcPort = readUint16BE(pktBuf, tcpStart);
            const dstPort = readUint16BE(pktBuf, tcpStart + 2);
            const dataOffset = ((pktBuf[tcpStart + 12] >> 4) & 0x0f) * 4;
            const flags = pktBuf[tcpStart + 13];
            const flagStr = decodeTcpFlags(flags);
            const payload = pktBuf.slice(tcpStart + dataOffset);
            // Track TCP flows
            const flowKey = `${srcIp}:${srcPort}-${dstIp}:${dstPort}`;
            const revKey = `${dstIp}:${dstPort}-${srcIp}:${srcPort}`;
            const existingKey = tcpFlowMap.has(flowKey) ? flowKey : tcpFlowMap.has(revKey) ? revKey : null;
            const flow = existingKey
                ? tcpFlowMap.get(existingKey)
                : { streamId: flowKey, srcIp, srcPort, dstIp, dstPort, packets: 0, bytes: 0, synSeen: false, finSeen: false, rstSeen: false, state: 'SYN_ONLY' };
            flow.packets++;
            flow.bytes += payload.length;
            if (flags & 0x02)
                flow.synSeen = true;
            if (flags & 0x01)
                flow.finSeen = true;
            if (flags & 0x04)
                flow.rstSeen = true;
            if (flow.synSeen && flow.finSeen)
                flow.state = 'CLOSED_FIN';
            else if (flow.rstSeen)
                flow.state = 'RESET';
            else if (flow.synSeen && flow.packets > 2)
                flow.state = 'ESTABLISHED';
            tcpFlowMap.set(existingKey || flowKey, flow);
            // HTTP Detection (ports 80, 8080, 8000, 8443)
            if ([80, 8080, 8000, 8443, 3000].includes(dstPort) && payload.length > 4) {
                const text = payload.toString('utf8', 0, Math.min(payload.length, 512));
                const methodMatch = text.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/);
                if (methodMatch) {
                    const hostMatch = text.match(/Host:\s*([^\r\n]+)/i);
                    const uaMatch = text.match(/User-Agent:\s*([^\r\n]+)/i);
                    result.httpRecords.push({
                        timestamp: tsStr,
                        method: methodMatch[1],
                        host: hostMatch?.[1]?.trim() || dstIp,
                        uri: methodMatch[2],
                        userAgent: uaMatch?.[1]?.trim() || 'Unknown',
                        isCleartextAuth: !!(text.includes('password=') || text.includes('Authorization: Basic')),
                    });
                }
            }
            // TLS ClientHello SNI Detection (port 443, 8443)
            if ([443, 8443].includes(dstPort) && payload.length > 43 && payload[0] === 0x16) {
                try {
                    const tlsVersion = (payload[1] << 8) | payload[2];
                    const hsType = payload[5];
                    if (hsType === 0x01) { // ClientHello
                        let hsOff = 9;
                        if (hsOff + 2 > payload.length)
                            continue;
                        const sessionIdLen = payload[hsOff + 32];
                        hsOff += 33 + sessionIdLen;
                        if (hsOff + 2 > payload.length)
                            continue;
                        const cipherLen = (payload[hsOff] << 8) | payload[hsOff + 1];
                        hsOff += 2 + cipherLen;
                        if (hsOff + 1 > payload.length)
                            continue;
                        const compLen = payload[hsOff];
                        hsOff += 1 + compLen;
                        if (hsOff + 2 > payload.length)
                            continue;
                        hsOff += 2; // extensions length
                        // Walk extensions for SNI (type 0x0000)
                        let sni = '';
                        while (hsOff + 4 <= payload.length) {
                            const extType = (payload[hsOff] << 8) | payload[hsOff + 1];
                            const extLen = (payload[hsOff + 2] << 8) | payload[hsOff + 3];
                            hsOff += 4;
                            if (extType === 0 && hsOff + 5 <= payload.length) {
                                const nameLen = (payload[hsOff + 3] << 8) | payload[hsOff + 4];
                                sni = payload.slice(hsOff + 5, hsOff + 5 + nameLen).toString('ascii');
                            }
                            hsOff += extLen;
                        }
                        result.tlsRecords.push({
                            timestamp: tsStr, clientIp: srcIp, serverIp: dstIp,
                            serverSni: sni || dstIp,
                            tlsVersion: TLS_VERSIONS[tlsVersion] || `0x${tlsVersion.toString(16)}`,
                        });
                    }
                }
                catch { /* skip malformed TLS */ }
            }
        }
        // ── UDP (proto 17) ────────────────────────────────────────────────────────
        else if (proto === 17 && pktBuf.length >= ipStart + ihl + 8) {
            protoName = 'UDP';
            const udpStart = ipStart + ihl;
            const srcPort = readUint16BE(pktBuf, udpStart);
            const dstPort = readUint16BE(pktBuf, udpStart + 2);
            // DNS Detection (port 53)
            if ((srcPort === 53 || dstPort === 53) && pktBuf.length > udpStart + 12) {
                try {
                    const dns = pktBuf.slice(udpStart + 8);
                    const qr = (dns[2] & 0x80) >> 7; // 0=query, 1=response
                    const qdCount = (dns[4] << 8) | dns[5];
                    const anCount = (dns[6] << 8) | dns[7];
                    let dnsOff = 12;
                    // Parse questions
                    const questions = [];
                    for (let q = 0; q < qdCount && dnsOff < dns.length; q++) {
                        const { name, end } = parseDnsName(dns, dnsOff);
                        dnsOff = end;
                        if (dnsOff + 4 > dns.length)
                            break;
                        const qtype = (dns[dnsOff] << 8) | dns[dnsOff + 1];
                        dnsOff += 4;
                        questions.push({ name, type: qtype });
                    }
                    // Parse answers (only from responses)
                    const resolvedIps = [];
                    if (qr === 1 && anCount > 0) {
                        for (let a = 0; a < anCount && dnsOff < dns.length; a++) {
                            const { end } = parseDnsName(dns, dnsOff);
                            dnsOff = end;
                            if (dnsOff + 10 > dns.length)
                                break;
                            const atype = (dns[dnsOff] << 8) | dns[dnsOff + 1];
                            const rdLen = (dns[dnsOff + 8] << 8) | dns[dnsOff + 9];
                            dnsOff += 10;
                            if (atype === 1 && rdLen === 4 && dnsOff + 4 <= dns.length) {
                                resolvedIps.push(ipFromBytes(dns, dnsOff));
                            }
                            dnsOff += rdLen;
                        }
                    }
                    for (const q of questions) {
                        const dga = calculateDgaScore(q.name);
                        result.dnsRecords.push({
                            timestamp: tsStr,
                            clientIp: qr === 0 ? srcIp : dstIp,
                            queryDomain: q.name,
                            recordType: DNS_TYPES[q.type] || String(q.type),
                            resolvedIps,
                            dgaScore: dga,
                            isSuspicious: dga > 5.0 || q.name.length > 50,
                        });
                    }
                }
                catch { /* skip malformed DNS */ }
            }
        }
        // ── ICMP (proto 1) ────────────────────────────────────────────────────────
        else if (proto === 1) {
            protoName = 'ICMP';
        }
        result.protocolCounts[protoName] = (result.protocolCounts[protoName] || 0) + 1;
        result.validPackets++;
    }
    result.captureDurationSec = lastTs > firstTs ? lastTs - firstTs : 0;
    // Build TCP flow list (top 20 by bytes)
    result.tcpFlows = Array.from(tcpFlowMap.values())
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 20);
    // ── Threat Detection ──────────────────────────────────────────────────────
    // 1. DGA domains
    const dgaDomains = result.dnsRecords.filter(d => d.dgaScore > 5.0);
    for (const d of dgaDomains.slice(0, 3)) {
        result.flaggedThreats.push({
            severity: 'High', category: 'DGA Domain / C2 Beaconing',
            details: `High-entropy DNS query: "${d.queryDomain}" (DGA score: ${d.dgaScore}/10). Possibly DGA-generated C2 domain.`,
        });
    }
    // 2. Cleartext auth
    const cleartextAuth = result.httpRecords.filter(h => h.isCleartextAuth);
    for (const h of cleartextAuth.slice(0, 3)) {
        result.flaggedThreats.push({
            severity: 'High', category: 'Cleartext Credential Submission',
            details: `HTTP ${h.method} to ${h.host}${h.uri} contains credentials in plaintext (no TLS encryption).`,
        });
    }
    // 3. Reset storms (RST TCP flows)
    const rstFlows = result.tcpFlows.filter(f => f.rstSeen && f.packets > 20);
    if (rstFlows.length > 0) {
        result.flaggedThreats.push({
            severity: 'Medium', category: 'TCP RST Storm / Port Scan',
            details: `${rstFlows.length} TCP flow(s) terminated with RST after high packet count — possible port scan or connection abuse.`,
        });
    }
    // 4. Long-duration DNS queries (>50 chars = tunnel risk)
    const longDns = result.dnsRecords.filter(d => d.queryDomain.length > 50);
    if (longDns.length > 2) {
        result.flaggedThreats.push({
            severity: 'High', category: 'DNS Tunneling Indicator',
            details: `${longDns.length} DNS queries with unusually long domain labels (>50 chars) — potential DNS tunneling for data exfiltration.`,
        });
    }
    return result;
}
