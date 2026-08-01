import http from 'http';
import { BaseCollector } from './baseCollector.js';
import { CollectorConfig, UnifiedSecurityEvent } from './collectorTypes.js';
import { IMessageQueue } from '../queue/messageQueue.js';
import { parseWindowsEventXml } from '../parsers/wef/wefXmlParser.js';
import { crypto } from '../utils/cryptoShim.js';
import { createLiveCollectorProvenance } from '../provenance/provenanceFactory.js';

export class WefCollectorService extends BaseCollector {
  private httpServer: http.Server | null = null;
  private boundPort: number = 0;
  private activeHttpConnections: number = 0;

  constructor(config: CollectorConfig, queue: IMessageQueue) {
    super(config, queue);
  }

  protected async onStart(): Promise<void> {
    const preferredPort = this.config.httpPort || 5516;
    await this.startHttpListener(preferredPort);
  }

  protected async onPause(): Promise<void> {
    // Drop handled in BaseCollector.ingestRawPacket
  }

  protected async onResume(): Promise<void> {
    // Ingest resumed
  }

  protected async onStop(): Promise<void> {
    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
      });
      this.httpServer = null;
    }
  }

  /**
   * Directly ingest raw WEF XML or JSON event from Express REST middleware or WinRM endpoint.
   */
  public async ingestWefPayload(
    rawXmlOrJson: string,
    sourceIp: string = '127.0.0.1',
    sourcePort: number = 0
  ): Promise<boolean> {
    return this.ingestRawPacket(
      rawXmlOrJson,
      sourceIp,
      sourcePort,
      'HTTP',
      this.boundPort || 5516
    );
  }

  protected async parseEvent(
    rawText: string,
    sourceIp: string,
    sourcePort: number,
    protocol: 'UDP' | 'TCP' | 'HTTP',
    destPort: number
  ): Promise<UnifiedSecurityEvent | null> {
    // 1. Check if payload is JSON string or XML
    let xmlContent = rawText;
    if (rawText.startsWith('{') && rawText.includes('"xml"')) {
      try {
        const parsedJson = JSON.parse(rawText);
        xmlContent = parsedJson.xml || rawText;
      } catch {}
    }

    // 2. Parse Windows Event XML
    const parsedWef = parseWindowsEventXml(xmlContent);

    // 3. Construct UnifiedSecurityEvent
    const unified: UnifiedSecurityEvent = {
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

  protected getListeningPorts(): number[] {
    return this.boundPort > 0 ? [this.boundPort] : [];
  }

  protected getActiveConnections(): number {
    return this.activeHttpConnections;
  }

  private async startHttpListener(preferredPort: number): Promise<void> {
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

          const success = await this.ingestRawPacket(
            body,
            remoteIp,
            remotePort,
            'HTTP',
            this.boundPort
          );

          if (success) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'INGESTED', collector: 'wef' }));
          } else {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Ingestion rate limited, paused, or buffer full' }));
          }
        });
      });

      server.on('error', (err) => {
        console.warn(`[WEF HTTP] Port ${preferredPort} failed (${err.message}). Trying fallback port 5517...`);
        if (preferredPort !== 5517) {
          this.startHttpListener(5517).then(resolve);
        } else {
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
