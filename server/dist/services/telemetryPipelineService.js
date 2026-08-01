import { query, memoryDb } from '../db/client.js';
import { evaluateSigmaRules } from './sigmaRuleEngine.js';
import { enrichWithThreatIntel } from './threatIntelService.js';
import { ingestSiemEvent } from './siemCollectorService.js';
import { broadcastTelemetryEvent } from './websocketService.js';
export class TelemetryPipelineService {
    queue;
    totalPipelineProcessed = 0;
    constructor(queue) {
        this.queue = queue;
    }
    initializePipeline() {
        console.log('[Telemetry Pipeline] Subscribing to queue channels (syslog, wef, netflow)...');
        this.queue.subscribe('telemetry.syslog', (msg) => this.handleTelemetryMessage(msg));
        this.queue.subscribe('telemetry.wef', (msg) => this.handleTelemetryMessage(msg));
        this.queue.subscribe('telemetry.netflow', (msg) => this.handleTelemetryMessage(msg));
    }
    getTotalProcessed() {
        return this.totalPipelineProcessed;
    }
    async handleTelemetryMessage(msg) {
        const event = msg.payload;
        if (!event || !event.id)
            return;
        this.totalPipelineProcessed++;
        // 1. Threat Intelligence Enrichment
        const threatLabel = enrichWithThreatIntel(event.ip);
        if (threatLabel) {
            event.severity = 'High';
            event.metadata.tags.push('threat-intel-matched');
            event.normalized.threatIntel = threatLabel;
        }
        // 2. Detection Engine Evaluation (Sigma Rules)
        const sigmaMatches = evaluateSigmaRules(event);
        if (sigmaMatches.length > 0) {
            for (const match of sigmaMatches) {
                event.metadata.tags.push(`sigma-${match.ruleId}`);
                const sourceCategory = event.collector === 'wef'
                    ? (event.product === 'Sysmon' ? 'Sysmon' : 'Windows_WEF')
                    : event.collector === 'netflow'
                        ? 'Switch_Router'
                        : (event.vendor === 'Cisco' || event.vendor === 'Palo Alto Networks' || event.vendor === 'Fortinet' ? 'Firewall' : 'Linux_Auditd');
                // Auto-create SIEM event for Sigma detections
                const siemEvent = ingestSiemEvent({
                    sourceCategory,
                    hostName: event.host,
                    severity: match.level === 'critical' ? 'Critical' : match.level === 'high' ? 'High' : 'Medium',
                    eventId: match.ruleId,
                    mitreTechnique: match.mitre.join(', '),
                    summary: `[${event.vendor} ${event.product}] ${match.ruleTitle}: ${event.event_type}`,
                    rawDetails: {
                        sigmaMatch: match,
                        unifiedEventId: event.id,
                        rawLog: event.raw,
                        normalized: event.normalized,
                    },
                });
                // Broadcast alert
                broadcastTelemetryEvent({
                    type: 'SIGMA_ALERT',
                    siemEvent,
                    unifiedEvent: event,
                    timestamp: new Date().toISOString(),
                });
            }
        }
        // 3. Database Persistence (PostgreSQL with Memory Fallback)
        try {
            await query(`INSERT INTO unified_security_events 
         (id, timestamp, collector, vendor, product, host, ip, severity, event_type, category, raw, normalized, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (id) DO NOTHING`, [
                event.id,
                event.timestamp,
                event.collector,
                event.vendor,
                event.product,
                event.host,
                event.ip,
                event.severity,
                event.event_type,
                event.category,
                event.raw,
                JSON.stringify(event.normalized),
                JSON.stringify(event.metadata),
            ]);
        }
        catch {
            // Memory fallback if DB query fails or unreached
        }
        // Always maintain recent memory buffer for instant UI queries
        memoryDb.unifiedEvents.unshift(event);
        if (memoryDb.unifiedEvents.length > 1000) {
            memoryDb.unifiedEvents.pop();
        }
        // 4. Real-Time WebSocket Broadcast
        broadcastTelemetryEvent({
            type: 'UNIFIED_EVENT',
            event,
            timestamp: new Date().toISOString(),
        });
    }
}
