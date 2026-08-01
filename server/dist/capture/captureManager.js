import { InterfaceManager } from './interfaceManager.js';
import { createProvenance } from '../provenance/provenanceFactory.js';
export class CaptureManager {
    static instance = null;
    activeSession = null;
    packetTimer = null;
    static getInstance() {
        if (!CaptureManager.instance) {
            CaptureManager.instance = new CaptureManager();
        }
        return CaptureManager.instance;
    }
    startCapture(config) {
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
    stopCapture() {
        if (!this.activeSession)
            return null;
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
    getStatus() {
        return this.activeSession;
    }
    recordPacket(bytes) {
        if (this.activeSession && this.activeSession.status === 'Running') {
            this.activeSession.packetsCaptured++;
            this.activeSession.bytesCaptured += bytes;
        }
    }
}
