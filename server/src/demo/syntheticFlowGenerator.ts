import { ingestNetFlowRecord } from '../services/networkFlowService.js';
import { broadcastTelemetryEvent } from '../services/websocketService.js';
import { loadPlatformConfig } from '../config/platformConfig.js';
import { createSyntheticDemoProvenance } from '../provenance/provenanceFactory.js';

export class SyntheticFlowGenerator {
  private static instance: SyntheticFlowGenerator | null = null;
  private intervalTimer: NodeJS.Timeout | null = null;
  private isRunning: boolean = false;
  private generatedCount: number = 0;

  public static getInstance(): SyntheticFlowGenerator {
    if (!SyntheticFlowGenerator.instance) {
      SyntheticFlowGenerator.instance = new SyntheticFlowGenerator();
    }
    return SyntheticFlowGenerator.instance;
  }

  public start(): boolean {
    const config = loadPlatformConfig();

    // STRICT GUARD: Do not start if synthetic data is disabled or not in DEMO mode
    if (!config.enableSyntheticData || config.platformMode !== 'DEMO') {
      console.log('[Synthetic Generator] Blocked: Platform mode is LIVE or ENABLE_SYNTHETIC_DATA is false.');
      return false;
    }

    if (this.isRunning) return true;

    this.isRunning = true;
    console.log('[Synthetic Generator] Starting controlled demonstration network flow generator (8s interval)...');

    const sampleSrcIps = ['192.168.1.105', '192.168.1.50', '192.168.1.120', '10.0.4.15', '185.220.101.5', '192.168.1.10'];
    const sampleDstIps = ['192.168.1.10', '8.8.8.8', '1.1.1.1', '192.168.1.50', '104.21.55.2'];
    const protocols: Array<'TCP' | 'UDP' | 'ICMP'> = ['TCP', 'TCP', 'TCP', 'UDP', 'ICMP'];
    const sources: Array<'NetFlow_v9' | 'IPFIX' | 'sFlow' | 'SPAN_Mirror'> = ['NetFlow_v9', 'IPFIX', 'sFlow', 'SPAN_Mirror'];

    this.intervalTimer = setInterval(() => {
      // Re-check config in case runtime mode changed
      if (!loadPlatformConfig().enableSyntheticData) {
        this.stop();
        return;
      }

      const srcIp = sampleSrcIps[Math.floor(Math.random() * sampleSrcIps.length)];
      const destIp = sampleDstIps[Math.floor(Math.random() * sampleDstIps.length)];
      const isInternalSrc = srcIp.startsWith('192.168.') || srcIp.startsWith('10.');
      const isInternalDst = destIp.startsWith('192.168.') || destIp.startsWith('10.');

      const direction: 'INBOUND' | 'OUTBOUND' | 'LATERAL' =
        isInternalSrc && isInternalDst ? 'LATERAL' : isInternalSrc ? 'OUTBOUND' : 'INBOUND';
      const protocol = protocols[Math.floor(Math.random() * protocols.length)];

      const provenance = createSyntheticDemoProvenance('flow-generator');

      const record = ingestNetFlowRecord({
        sourceType: sources[Math.floor(Math.random() * sources.length)],
        srcIp,
        srcPort: Math.floor(Math.random() * 45000) + 1024,
        destIp,
        destPort: [80, 443, 53, 445, 3389, 4444][Math.floor(Math.random() * 6)],
        protocol,
        bytes: Math.floor(Math.random() * 200000) + 128,
        packets: Math.floor(Math.random() * 150) + 1,
        durationMs: Math.floor(Math.random() * 2000) + 50,
        flags: protocol === 'TCP' ? ['SYN', 'ACK-PUSH', 'SYN-ACK', 'RST'][Math.floor(Math.random() * 4)] : '',
        direction,
        vlanId: isInternalSrc ? 10 : 1,
        geoCountry: isInternalSrc ? 'INTERNAL' : ['US', 'DE', 'RU', 'CN'][Math.floor(Math.random() * 4)],
        provenance,
      });

      this.generatedCount++;

      broadcastTelemetryEvent({
        type: 'NETFLOW_RECORD',
        record,
        provenance,
        timestamp: new Date().toISOString(),
      });
    }, 8000);

    return true;
  }

  public stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
    this.isRunning = false;
    console.log('[Synthetic Generator] Generator stopped.');
  }

  public getStatus(): { isRunning: boolean; generatedCount: number } {
    return {
      isRunning: this.isRunning,
      generatedCount: this.generatedCount,
    };
  }
}
