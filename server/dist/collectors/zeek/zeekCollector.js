import crypto from 'crypto';
import { createProvenance } from '../../provenance/provenanceFactory.js';
import { memoryDb } from '../../db/client.js';
export class ZeekCollectorService {
    static instance = null;
    logCounts = { conn: 0, dns: 0, http: 0, ssl: 0, notice: 0 };
    lastEventAt = new Date().toISOString();
    static getInstance() {
        if (!ZeekCollectorService.instance) {
            ZeekCollectorService.instance = new ZeekCollectorService();
        }
        return ZeekCollectorService.instance;
    }
    parseZeekLog(logType, entry) {
        this.logCounts[logType] = (this.logCounts[logType] || 0) + 1;
        this.lastEventAt = new Date().toISOString();
        const timestamp = typeof entry.ts === 'number'
            ? new Date(entry.ts * 1000).toISOString()
            : entry.ts || new Date().toISOString();
        const srcIp = entry['id.orig_h'] || '192.168.1.100';
        const destIp = entry['id.resp_h'] || '10.0.0.1';
        const srcPort = entry['id.orig_p'] || 0;
        const destPort = entry['id.resp_p'] || 0;
        let severity = 'Info';
        let eventType = `ZEEK_${logType.toUpperCase()}`;
        let category = 'Network';
        if (logType === 'notice') {
            severity = 'High';
            category = 'Alert';
        }
        else if (logType === 'conn' && (entry.conn_state === 'REJ' || entry.conn_state === 'RSTO')) {
            severity = 'Medium';
        }
        const provenance = createProvenance({
            telemetrySource: 'ZEEK_LOG',
            collectionMethod: 'FILE_IMPORT',
            isSynthetic: false,
            collectorId: `zeek-sensor-${logType}`,
        });
        const unified = {
            id: crypto.randomUUID(),
            timestamp,
            collector: 'syslog', // mapped cleanly to unified schema
            vendor: 'Zeek',
            product: `Zeek-${logType}.log`,
            host: srcIp,
            ip: srcIp,
            severity,
            event_type: eventType,
            category,
            raw: JSON.stringify(entry),
            normalized: {
                uid: entry.uid,
                sourceIp: srcIp,
                sourcePort: srcPort,
                destinationIp: destIp,
                destinationPort: destPort,
                protocol: entry.proto || 'TCP',
                service: entry.service,
                duration: entry.duration,
                query: entry.query,
                httpMethod: entry.method,
                httpHost: entry.host,
                httpUri: entry.uri,
                serverName: entry.server_name,
                noticeNote: entry.note,
                noticeMessage: entry.msg,
            },
            metadata: {
                ingestTimestamp: new Date().toISOString(),
                protocol: entry.proto?.toUpperCase() || 'TCP',
                sourcePort: srcPort,
                destinationPort: destPort,
                tags: ['zeek', logType],
            },
            provenance,
        };
        memoryDb.unifiedEvents.unshift(unified);
        if (memoryDb.unifiedEvents.length > 1000)
            memoryDb.unifiedEvents.pop();
        return unified;
    }
    getSensorStatus() {
        return {
            status: 'Healthy',
            totalEvents: Object.values(this.logCounts).reduce((a, b) => a + b, 0),
            logCounts: this.logCounts,
            lastEventAt: this.lastEventAt,
        };
    }
}
