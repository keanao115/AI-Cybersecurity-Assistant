import dgram from 'dgram';
import net from 'net';
import { BaseCollector } from './baseCollector.js';
import { CollectorConfig, UnifiedSecurityEvent } from './collectorTypes.js';
import { IMessageQueue } from '../queue/messageQueue.js';
import { parseSyslogHeader } from '../parsers/syslog/syslogRfcParser.js';
import { SyslogVendorRegistry } from '../parsers/syslog/syslogVendorRegistry.js';
import { crypto } from '../utils/cryptoShim.js';
import { createLiveCollectorProvenance } from '../provenance/provenanceFactory.js';

export class SyslogCollectorService extends BaseCollector {
  private udpSocket: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private activeTcpConnections: Set<net.Socket> = new Set();
  private vendorRegistry: SyslogVendorRegistry;
  private boundUdpPort: number = 0;
  private boundTcpPort: number = 0;

  constructor(config: CollectorConfig, queue: IMessageQueue) {
    super(config, queue);
    this.vendorRegistry = new SyslogVendorRegistry();
  }

  protected async onStart(): Promise<void> {
    const preferredUdpPort = this.config.udpPort || 514;
    const preferredTcpPort = this.config.tcpPort || 514;

    // Start UDP Listener
    await this.startUdpListener(preferredUdpPort);

    // Start TCP Listener
    await this.startTcpListener(preferredTcpPort);
  }

  protected async onPause(): Promise<void> {
    // Ingest drops handled automatically in BaseCollector.ingestRawPacket
  }

  protected async onResume(): Promise<void> {
    // Ingest resumed automatically
  }

  protected async onStop(): Promise<void> {
    // Close UDP Socket
    if (this.udpSocket) {
      try {
        this.udpSocket.close();
      } catch {}
      this.udpSocket = null;
    }

    // Close Active TCP Connections
    for (const socket of this.activeTcpConnections) {
      try {
        socket.destroy();
      } catch {}
    }
    this.activeTcpConnections.clear();

    // Close TCP Server
    if (this.tcpServer) {
      await new Promise<void>((resolve) => {
        this.tcpServer!.close(() => resolve());
      });
      this.tcpServer = null;
    }
  }

  protected async parseEvent(
    rawText: string,
    sourceIp: string,
    sourcePort: number,
    protocol: 'UDP' | 'TCP' | 'HTTP',
    destPort: number
  ): Promise<UnifiedSecurityEvent | null> {
    // 1. RFC 3164 / 5424 Header Parsing
    const header = parseSyslogHeader(rawText);

    // 2. Modular Vendor Parser Matching
    const vendorResult = this.vendorRegistry.parse(header, rawText);

    // 3. Construct UnifiedSecurityEvent
    const unified: UnifiedSecurityEvent = {
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
      provenance: createLiveCollectorProvenance('syslog', `syslog-${protocol.toLowerCase()}-${destPort}`, header.timestamp),
    };

    return unified;
  }

  protected getListeningPorts(): number[] {
    const ports: number[] = [];
    if (this.boundUdpPort > 0) ports.push(this.boundUdpPort);
    if (this.boundTcpPort > 0) ports.push(this.boundTcpPort);
    return ports;
  }

  protected getActiveConnections(): number {
    return this.activeTcpConnections.size;
  }

  // ─── Socket Bind Helpers with Fallback ────────────────────────────────────

  private async startUdpListener(preferredPort: number): Promise<void> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');

      socket.on('message', (msg, rinfo) => {
        this.ingestRawPacket(
          msg.toString('utf8'),
          rinfo.address,
          rinfo.port,
          'UDP',
          this.boundUdpPort
        );
      });

      socket.on('error', (err) => {
        const fallbackPort = preferredPort === 514 ? 5514 : preferredPort === 5514 ? 5518 : 0;
        if (fallbackPort > 0) {
          console.warn(`[Syslog UDP] Port ${preferredPort} failed (${err.message}). Trying fallback port ${fallbackPort}...`);
          try {
            socket.close();
          } catch {}
          this.startUdpListener(fallbackPort).then(resolve);
        } else {
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

  private async startTcpListener(preferredPort: number): Promise<void> {
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
              this.ingestRawPacket(
                line,
                socket.remoteAddress || '127.0.0.1',
                socket.remotePort || 0,
                'TCP',
                this.boundTcpPort
              );
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
        } else {
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
