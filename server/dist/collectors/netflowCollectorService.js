import dgram from 'dgram';
import { BaseCollector } from './baseCollector.js';
import { decodeNetflowBuffer } from '../parsers/netflow/netflowDecoder.js';
import { crypto } from '../utils/cryptoShim.js';
export class NetflowCollectorService extends BaseCollector {
    udpSocket = null;
    boundPort = 0;
    constructor(config, queue) {
        super(config, queue);
    }
    async onStart() {
        const preferredPort = this.config.udpPort || 2055;
        await this.startUdpListener(preferredPort);
    }
    async onPause() {
        // Drop handled in BaseCollector.ingestRawPacket
    }
    async onResume() {
        // Ingest resumed
    }
    async onStop() {
        if (this.udpSocket) {
            try {
                this.udpSocket.close();
            }
            catch { }
            this.udpSocket = null;
        }
    }
    async parseEvent(rawText, sourceIp, sourcePort, protocol, destPort) {
        // Raw binary buffer was passed via buffer.toString('hex') or binary
        const hexBuffer = Buffer.from(rawText, 'hex');
        const records = decodeNetflowBuffer(hexBuffer, sourceIp);
        if (records.length === 0)
            return null;
        // Use the first record as primary event
        const record = records[0];
        return this.transformRecordToUnifiedEvent(record, rawText, protocol, sourcePort, destPort);
    }
    /**
     * Transforms a single decoded NetFlow record into a UnifiedSecurityEvent.
     */
    transformRecordToUnifiedEvent(record, rawHex, protocol, sourcePort, destPort) {
        return {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            collector: 'netflow',
            vendor: 'Generic',
            product: `NetFlow-v${record.version}`,
            host: record.exporterIp,
            ip: record.sourceIp,
            severity: record.severity,
            event_type: 'NETFLOW_FLOW_RECORD',
            category: 'Network',
            raw: rawHex,
            normalized: {
                sourceIp: record.sourceIp,
                destinationIp: record.destinationIp,
                sourcePort: record.sourcePort,
                destinationPort: record.destinationPort,
                protocol: record.protocol,
                protocolNumber: record.protocolNumber,
                bytes: record.bytes,
                packets: record.packets,
                durationMs: record.durationMs,
                inputInterface: record.inputInterface,
                outputInterface: record.outputInterface,
                exporterIp: record.exporterIp,
            },
            metadata: {
                ingestTimestamp: new Date().toISOString(),
                protocol,
                sourcePort,
                destinationPort: destPort,
                bytes: record.bytes,
                packets: record.packets,
                durationMs: record.durationMs,
                tags: ['netflow', `v${record.version}`, record.protocol.toLowerCase()],
            },
        };
    }
    getListeningPorts() {
        return this.boundPort > 0 ? [this.boundPort] : [];
    }
    getActiveConnections() {
        return 0; // UDP connectionless
    }
    async startUdpListener(preferredPort) {
        return new Promise((resolve) => {
            const socket = dgram.createSocket('udp4');
            socket.on('message', async (msg, rinfo) => {
                const hexPayload = msg.toString('hex');
                const records = decodeNetflowBuffer(msg, rinfo.address);
                if (records.length > 0) {
                    for (const record of records) {
                        const unified = this.transformRecordToUnifiedEvent(record, hexPayload, 'UDP', rinfo.port, this.boundPort);
                        await this.queue.publish(`telemetry.netflow`, unified);
                        this.eventsProcessedTotal++;
                        this.bytesProcessedTotal += msg.length;
                        this.lastEventTimeMs = Date.now();
                    }
                }
                else {
                    this.ingestRawPacket(hexPayload, rinfo.address, rinfo.port, 'UDP', this.boundPort);
                }
            });
            socket.on('error', (err) => {
                console.warn(`[NetFlow UDP] Port ${preferredPort} failed (${err.message}). Trying fallback port 2056...`);
                try {
                    socket.close();
                }
                catch { }
                if (preferredPort !== 2056) {
                    this.startUdpListener(2056).then(resolve);
                }
                else {
                    resolve();
                }
            });
            socket.bind(preferredPort, () => {
                this.udpSocket = socket;
                this.boundPort = preferredPort;
                console.log(`[NetFlow UDP] Listening for NetFlow v5/v9/IPFIX on port ${preferredPort}`);
                resolve();
            });
        });
    }
}
