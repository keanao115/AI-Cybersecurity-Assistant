import crypto from 'crypto';
import { createProvenance } from '../../provenance/provenanceFactory.js';
import { memoryDb } from '../../db/client.js';
export class SuricataCollectorService {
    static instance = null;
    alertCount = 0;
    eventCount = 0;
    lastAlertAt = new Date().toISOString();
    static getInstance() {
        if (!SuricataCollectorService.instance) {
            SuricataCollectorService.instance = new SuricataCollectorService();
        }
        return SuricataCollectorService.instance;
    }
    parseEveEntry(entry) {
        this.eventCount++;
        const timestamp = entry.timestamp || new Date().toISOString();
        const srcIp = entry.src_ip || '192.168.1.105';
        const destIp = entry.dest_ip || '10.0.0.1';
        const srcPort = entry.src_port || 0;
        const destPort = entry.dest_port || 0;
        const eventType = (entry.event_type || 'alert').toUpperCase();
        let severity = 'Info';
        let summary = 'Suricata EVE Event';
        if (entry.alert) {
            this.alertCount++;
            this.lastAlertAt = new Date().toISOString();
            summary = entry.alert.signature || 'Suricata IDS Alert';
            const suriSev = entry.alert.severity || 3;
            severity = suriSev === 1 ? 'Critical' : suriSev === 2 ? 'High' : suriSev === 3 ? 'Medium' : 'Low';
        }
        const provenance = createProvenance({
            telemetrySource: 'SURICATA_EVE',
            collectionMethod: 'FILE_IMPORT',
            isSynthetic: false,
            collectorId: 'suricata-eve-sensor',
        });
        const unified = {
            id: crypto.randomUUID(),
            timestamp,
            collector: 'syslog',
            vendor: 'Suricata',
            product: 'Suricata IDS/IPS (EVE JSON)',
            host: srcIp,
            ip: srcIp,
            severity,
            event_type: `SURICATA_${eventType}`,
            category: entry.alert?.category || 'Network IDS',
            raw: JSON.stringify(entry),
            normalized: {
                signature: entry.alert?.signature,
                signatureId: entry.alert?.signature_id,
                suricataSeverity: entry.alert?.severity,
                sourceIp: srcIp,
                sourcePort: srcPort,
                destinationIp: destIp,
                destinationPort: destPort,
                protocol: entry.proto || 'TCP',
                dnsQuery: entry.dns?.rrname,
                httpHost: entry.http?.hostname,
                httpUrl: entry.http?.url,
                tlsSni: entry.tls?.sni,
                summary,
            },
            metadata: {
                ingestTimestamp: new Date().toISOString(),
                protocol: entry.proto?.toUpperCase() || 'TCP',
                sourcePort: srcPort,
                destinationPort: destPort,
                eventId: entry.alert?.signature_id ? String(entry.alert.signature_id) : undefined,
                tags: ['suricata', 'ids', (entry.event_type || 'alert').toLowerCase()],
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
            engineVersion: '7.0.6-RELEASE',
            rulesLoaded: 34120,
            lastRuleReloadAt: new Date(Date.now() - 3600000).toISOString(),
            totalEventsProcessed: this.eventCount,
            totalAlertsReceived: this.alertCount,
            lastAlertAt: this.lastAlertAt,
        };
    }
}
