import dgram from 'dgram';
import net from 'net';
import { BaseCollector } from './baseCollector.js';
import { parseSyslogHeader } from '../parsers/syslog/syslogRfcParser.js';
import { SyslogVendorRegistry } from '../parsers/syslog/syslogVendorRegistry.js';
import { crypto } from '../utils/cryptoShim.js';
export class SyslogCollectorService extends BaseCollector {
    udpSocket = null;
    tcpServer = null;
    activeTcpConnections = new Set();
    vendorRegistry;
    boundUdpPort = 0;
    boundTcpPort = 0;
    constructor(config, queue) {
        super(config, queue);
        this.vendorRegistry = new SyslogVendorRegistry();
    }
    async onStart() {
        const preferredUdpPort = this.config.udpPort || 514;
        const preferredTcpPort = this.config.tcpPort || 514;
        // Start UDP Listener
        await this.startUdpListener(preferredUdpPort);
        // Start TCP Listener
        await this.startTcpListener(preferredTcpPort);
    }
    async onPause() {
        // Ingest drops handled automatically in BaseCollector.ingestRawPacket
    }
    async onResume() {
        // Ingest resumed automatically
    }
    async onStop() {
        // Close UDP Socket
        if (this.udpSocket) {
            try {
                this.udpSocket.close();
            }
            catch { }
            this.udpSocket = null;
        }
        // Close Active TCP Connections
        for (const socket of this.activeTcpConnections) {
            try {
                socket.destroy();
            }
            catch { }
        }
        this.activeTcpConnections.clear();
        // Close TCP Server
        if (this.tcpServer) {
            await new Promise((resolve) => {
                this.tcpServer.close(() => resolve());
            });
            this.tcpServer = null;
        }
    }
    async parseEvent(rawText, sourceIp, sourcePort, protocol, destPort) {
        // 1. RFC 3164 / 5424 Header Parsing
        const header = parseSyslogHeader(rawText);
        // 2. Modular Vendor Parser Matching
        const vendorResult = this.vendorRegistry.parse(header, rawText);
        // 3. Construct UnifiedSecurityEvent
        const unified = {
            id: crypto.randomUUID(),
            timestamp: header.timestamp,
            collector: 'syslog',
            vendor: vendorResult.vendor,
            product: vendorResult.product,
            host: vendorResult.host || header.hostname,
            ip: vendorResult.ip || sourceIp,
            severity: vendorResult.severity || header.severity,
            event_type: vendorResult.eventType,
            category: vendorResult.category,
            raw: rawText,
            normalized: {
                facility: header.facility,
                appName: header.appName,
                procId: header.procId,
                message: header.message,
                ...vendorResult.normalizedFields,
            },
            metadata: {
                ingestTimestamp: new Date().toISOString(),
                protocol,
                sourcePort,
                destinationPort: destPort,
                facility: header.facility,
                tags: ['syslog', ...vendorResult.tags],
            },
        };
        return unified;
    }
    getListeningPorts() {
        const ports = [];
        if (this.boundUdpPort > 0)
            ports.push(this.boundUdpPort);
        if (this.boundTcpPort > 0)
            ports.push(this.boundTcpPort);
        return ports;
    }
    getActiveConnections() {
        return this.activeTcpConnections.size;
    }
    // ─── Socket Bind Helpers with Fallback ────────────────────────────────────
    async startUdpListener(preferredPort) {
        return new Promise((resolve) => {
            const socket = dgram.createSocket('udp4');
            socket.on('message', (msg, rinfo) => {
                this.ingestRawPacket(msg.toString('utf8'), rinfo.address, rinfo.port, 'UDP', this.boundUdpPort);
            });
            socket.on('error', (err) => {
                const fallbackPort = preferredPort === 514 ? 5514 : preferredPort === 5514 ? 5518 : 0;
                if (fallbackPort > 0) {
                    console.warn(`[Syslog UDP] Port ${preferredPort} failed (${err.message}). Trying fallback port ${fallbackPort}...`);
                    try {
                        socket.close();
                    }
                    catch { }
                    this.startUdpListener(fallbackPort).then(resolve);
                }
                else {
                    console.error(`[Syslog UDP] Unable to bind UDP port: ${err.message}`);
                    resolve();
                }
            });
            socket.bind(preferredPort, () => {
                this.udpSocket = socket;
                this.boundUdpPort = preferredPort;
                console.log(`[Syslog UDP] Listening on port ${preferredPort}`);
                resolve();
            });
        });
    }
    async startTcpListener(preferredPort) {
        return new Promise((resolve) => {
            const server = net.createServer((socket) => {
                this.activeTcpConnections.add(socket);
                let buffer = '';
                socket.on('data', (chunk) => {
                    buffer += chunk.toString('utf8');
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || ''; // keep trailing un-terminated string
                    for (const line of lines) {
                        if (line.trim()) {
                            this.ingestRawPacket(line, socket.remoteAddress || '127.0.0.1', socket.remotePort || 0, 'TCP', this.boundTcpPort);
                        }
                    }
                });
                socket.on('close', () => {
                    this.activeTcpConnections.delete(socket);
                });
                socket.on('error', () => {
                    this.activeTcpConnections.delete(socket);
                });
            });
            server.on('error', (err) => {
                console.warn(`[Syslog TCP] Port ${preferredPort} failed (${err.message}). Trying fallback port 5515...`);
                if (preferredPort !== 5515) {
                    this.startTcpListener(5515).then(resolve);
                }
                else {
                    resolve();
                }
            });
            server.listen(preferredPort, () => {
                this.tcpServer = server;
                this.boundTcpPort = preferredPort;
                console.log(`[Syslog TCP] Listening on port ${preferredPort}`);
                resolve();
            });
        });
    }
}
