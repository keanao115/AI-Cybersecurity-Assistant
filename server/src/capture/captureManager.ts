import { InterfaceManager, NetworkInterfaceInfo } from './interfaceManager.js';
import { loadPlatformConfig } from '../config/platformConfig.js';
import { createProvenance } from '../provenance/provenanceFactory.js';
import { TelemetryProvenance } from '../types/telemetryProvenance.js';
import { broadcastTelemetryEvent } from '../services/websocketService.js';

export interface CaptureSessionConfig {
  interfaceId: string;
  bpfFilter?: string;
  promiscuousMode?: boolean;
  snapLength?: number;
}

export interface CaptureSessionStatus {
  sessionId: string;
  interfaceInfo: NetworkInterfaceInfo;
  bpfFilter: string;
  promiscuousMode: boolean;
  status: 'Starting' | 'Running' | 'Paused' | 'Stopped' | 'Failed';
  startedAt: string;
  stoppedAt?: string;
  packetsCaptured: number;
  packetsDropped: number;
  bytesCaptured: number;
  provenance: TelemetryProvenance;
}

export class CaptureManager {
  private static instance: CaptureManager | null = null;
  private activeSession: CaptureSessionStatus | null = null;
  private packetTimer: NodeJS.Timeout | null = null;

  public static getInstance(): CaptureManager {
    if (!CaptureManager.instance) {
      CaptureManager.instance = new CaptureManager();
    }
    return CaptureManager.instance;
  }

  public startCapture(config: CaptureSessionConfig): CaptureSessionStatus {
    const iface = InterfaceManager.getInterfaceById(config.interfaceId);
    if (!iface) {
      throw new Error(`Network interface "${config.interfaceId}" not found.`);
    }

    if (this.activeSession && this.activeSession.status === 'Running') {
      this.stopCapture();
    }

    const sessionId = `CAP-${Date.now()}`;
    const provenance = createProvenance({
      telemetrySource: 'NETFLOW_COLLECTOR',
      collectionMethod: 'LIVE_CAPTURE',
      isSynthetic: false,
      isSeeded: false,
      isReplay: false,
      collectorId: `pcap-driver-${iface.name}`,
    });

    this.activeSession = {
      sessionId,
      interfaceInfo: iface,
      bpfFilter: config.bpfFilter || 'ip',
      promiscuousMode: config.promiscuousMode ?? true,
      status: 'Running',
      startedAt: new Date().toISOString(),
      packetsCaptured: 0,
      packetsDropped: 0,
      bytesCaptured: 0,
      provenance,
    };

    console.log(`[Capture Manager] Started live packet capture session ${sessionId} on ${iface.name} (Filter: "${this.activeSession.bpfFilter}")`);
    return this.activeSession;
  }

  public stopCapture(): CaptureSessionStatus | null {
    if (!this.activeSession) return null;

    if (this.packetTimer) {
      clearInterval(this.packetTimer);
      this.packetTimer = null;
    }

    this.activeSession.status = 'Stopped';
    this.activeSession.stoppedAt = new Date().toISOString();
    console.log(`[Capture Manager] Stopped capture session ${this.activeSession.sessionId}. Total packets: ${this.activeSession.packetsCaptured}`);

    const stoppedSession = { ...this.activeSession };
    this.activeSession = null;
    return stoppedSession;
  }

  public getStatus(): CaptureSessionStatus | null {
    return this.activeSession;
  }

  public recordPacket(bytes: number): void {
    if (this.activeSession && this.activeSession.status === 'Running') {
      this.activeSession.packetsCaptured++;
      this.activeSession.bytesCaptured += bytes;
    }
  }
}
