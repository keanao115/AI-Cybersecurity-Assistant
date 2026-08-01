import http from 'http';
import { BaseCollector } from './baseCollector.js';
import { parseWindowsEventXml } from '../parsers/wef/wefXmlParser.js';
import { crypto } from '../utils/cryptoShim.js';
import { createLiveCollectorProvenance } from '../provenance/provenanceFactory.js';
export class WefCollectorService extends BaseCollector {
    httpServer = null;
    boundPort = 0;
    activeHttpConnections = 0;
    constructor(config, queue) {
        super(config, queue);
    }
    async onStart() {
        const preferredPort = this.config.httpPort || 5516;
        await this.startHttpListener(preferredPort);
    }
    async onPause() {
        // Drop handled in BaseCollector.ingestRawPacket
    }
    async onResume() {
        // Ingest resumed
    }
    async onStop() {
        if (this.httpServer) {
            await new Promise((resolve) => {
                this.httpServer.close(() => resolve());
            });
            this.httpServer = null;
        }
    }
    /**
     * Directly ingest raw WEF XML or JSON event from Express REST middleware or WinRM endpoint.
     */
    async ingestWefPayload(rawXmlOrJson, sourceIp = '127.0.0.1', sourcePort = 0) {
        return this.ingestRawPacket(rawXmlOrJson, sourceIp, sourcePort, 'HTTP', this.boundPort || 5516);
    }
    async parseEvent(rawText, sourceIp, sourcePort, protocol, destPort) {
        // 1. Check if payload is JSON string or XML
        let xmlContent = rawText;
        if (rawText.startsWith('{') && rawText.includes('"xml"')) {
            try {
                const parsedJson = JSON.parse(rawText);
                xmlContent = parsedJson.xml || rawText;
            }
            catch { }
        }
        // 2. Parse Windows Event XML
        const parsedWef = parseWindowsEventXml(xmlContent);
        // 3. Construct UnifiedSecurityEvent
        const unified = {
            id: crypto.randomUUID(),
            timestamp: parsedWef.timestamp,
            collector: 'wef',
            vendor: 'Microsoft',
            product: parsedWef.provider.includes('Sysmon') ? 'Sysmon' : 'Windows Event Forwarding',
            host: parsedWef.computer,
            ip: parsedWef.eventData.IpAddress || sourceIp,
            severity: parsedWef.severity,
            event_type: parsedWef.eventType,
            category: parsedWef.category,
            raw: rawText,
            normalized: {
                eventId: parsedWef.eventId,
                provider: parsedWef.provider,
                channel: parsedWef.channel,
                computer: parsedWef.computer,
                userSid: parsedWef.userSid,
                level: parsedWef.level,
                task: parsedWef.task,
                keywords: parsedWef.keywords,
                ...parsedWef.eventData,
            },
            metadata: {
                ingestTimestamp: new Date().toISOString(),
                protocol,
                sourcePort,
                destinationPort: destPort,
                eventId: parsedWef.eventId,
                tags: ['windows', 'wef', parsedWef.channel.toLowerCase()],
            },
            provenance: createLiveCollectorProvenance('wef', `wef-http-${destPort}`, parsedWef.timestamp),
        };
        return unified;
    }
    getListeningPorts() {
        return this.boundPort > 0 ? [this.boundPort] : [];
    }
    getActiveConnections() {
        return this.activeHttpConnections;
    }
    async startHttpListener(preferredPort) {
        return new Promise((resolve) => {
            const server = http.createServer(async (req, res) => {
                if (req.method !== 'POST') {
                    res.writeHead(45, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Only POST supported for WEF ingestion' }));
                    return;
                }
                this.activeHttpConnections++;
                let body = '';
                req.on('data', (chunk) => {
                    body += chunk.toString('utf8');
                    if (body.length > this.config.maxPacketSizeBytes) {
                        req.destroy();
                    }
                });
                req.on('end', async () => {
                    this.activeHttpConnections = Math.max(0, this.activeHttpConnections - 1);
                    const remoteIp = req.socket.remoteAddress || '127.0.0.1';
                    const remotePort = req.socket.remotePort || 0;
                    const success = await this.ingestRawPacket(body, remoteIp, remotePort, 'HTTP', this.boundPort);
                    if (success) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ status: 'INGESTED', collector: 'wef' }));
                    }
                    else {
                        res.writeHead(429, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Ingestion rate limited, paused, or buffer full' }));
                    }
                });
            });
            server.on('error', (err) => {
                console.warn(`[WEF HTTP] Port ${preferredPort} failed (${err.message}). Trying fallback port 5517...`);
                if (preferredPort !== 5517) {
                    this.startHttpListener(5517).then(resolve);
                }
                else {
                    resolve();
                }
            });
            server.listen(preferredPort, () => {
                this.httpServer = server;
                this.boundPort = preferredPort;
                console.log(`[WEF HTTP] Listening for Windows Event Forwarding XML on port ${preferredPort}`);
                resolve();
            });
        });
    }
}
