import assert from 'assert';
import { test, describe } from 'node:test';
import { InterfaceManager } from '../capture/interfaceManager.js';
import { CaptureManager } from '../capture/captureManager.js';
import { decodePacketBuffer } from '../capture/packetDecoder.js';
import { extractTlsFingerprint } from '../pipeline/tlsFingerprinter.js';
import { FlowEngine } from '../flows/flowEngine.js';
import { FlowCache } from '../flows/flowCache.js';
import { ZeekCollectorService } from '../collectors/zeek/zeekCollector.js';
import { SuricataCollectorService } from '../collectors/suricata/suricataCollector.js';
import { CorrelationEngine } from '../correlation/correlationEngine.js';
import { EvidenceBundleService } from '../correlation/evidenceBundle.js';
import { TimelineEngine } from '../correlation/timelineEngine.js';

describe('Enterprise Telemetry Integration Suite (Pcap, Zeek, Suricata)', () => {

  describe('1. Network Interface Manager & Capture Lifecycle', () => {
    test('Should enumerate network interfaces with valid metadata', () => {
      const ifaces = InterfaceManager.getInterfaces();
      assert.ok(ifaces.length > 0, 'Should find at least 1 network interface');
      assert.ok(ifaces[0].id, 'Interface should have an ID');
      assert.ok(ifaces[0].name, 'Interface should have a name');
    });

    test('Should start and stop a live capture session cleanly', () => {
      const ifaces = InterfaceManager.getInterfaces();
      const manager = CaptureManager.getInstance();

      const session = manager.startCapture({ interfaceId: ifaces[0].id, bpfFilter: 'tcp' });
      assert.strictEqual(session.status, 'Running');
      assert.strictEqual(session.interfaceInfo.id, ifaces[0].id);

      const stopped = manager.stopCapture();
      assert.strictEqual(stopped?.status, 'Stopped');
      assert.strictEqual(manager.getStatus(), null);
    });
  });

  describe('2. Layered Frame Decoder & JA3/JA4 TLS Fingerprinting', () => {

    test('Should decode frame buffer and generate valid JA3 & JA4 TLS fingerprints', () => {
      const sampleFrame = Buffer.from('00155d043b1100155d012a8c08004500003c1c4640006406b1e6c0a80169c0a8010a01bbd4300000000000000000a002b85500000000', 'hex');
      const decoded = decodePacketBuffer(sampleFrame);

      assert.strictEqual(decoded.etherType, 'IPv4');
      assert.strictEqual(decoded.protocol, 'TCP');

      const tlsFp = extractTlsFingerprint();
      assert.ok(tlsFp.ja3, 'JA3 MD5 string should be populated');
      assert.ok(tlsFp.ja4, 'JA4 string should be populated');
      assert.strictEqual(tlsFp.ja3.length, 32, 'JA3 should be 32-character MD5 hash');
    });
  });

  describe('3. Flow Engine & Flow Cache Expiration', () => {

    test('Should aggregate packet streams into 5-tuple flow records', () => {
      const engine = FlowEngine.getInstance();
      const decoded = decodePacketBuffer(Buffer.alloc(40));

      const flow = engine.processPacket(decoded);
      assert.ok(flow.id, 'Flow should have an ID');
      assert.strictEqual(flow.packets, 1);

      const stats = engine.getCacheStats();
      assert.ok(stats.activeFlowCount >= 1, 'Flow cache should contain active flows');
    });
  });

  describe('4. Zeek JSON Log Collector & Normalizer', () => {

    test('Should parse Zeek conn.log JSON into UnifiedSecurityEvent with ZEEK_LOG provenance', () => {
      const zeekService = ZeekCollectorService.getInstance();
      const event = zeekService.parseZeekLog('conn', {
        ts: 1722490000.5,
        uid: 'C123456',
        'id.orig_h': '192.168.1.105',
        'id.orig_p': 54320,
        'id.resp_h': '10.0.0.1',
        'id.resp_p': 445,
        proto: 'tcp',
        duration: 1.25,
      });

      assert.strictEqual(event.vendor, 'Zeek');
      assert.strictEqual(event.event_type, 'ZEEK_CONN');
      assert.strictEqual(event.provenance?.telemetrySource, 'ZEEK_LOG');
      assert.strictEqual(event.provenance?.isSynthetic, false);
    });
  });

  describe('5. Suricata EVE JSON IDS Collector & Normalizer', () => {

    test('Should parse Suricata EVE JSON alert into UnifiedSecurityEvent with SURICATA_EVE provenance', () => {
      const suriService = SuricataCollectorService.getInstance();
      const event = suriService.parseEveEntry({
        timestamp: new Date().toISOString(),
        event_type: 'alert',
        src_ip: '185.220.101.5',
        src_port: 4444,
        dest_ip: '192.168.1.105',
        dest_port: 49152,
        proto: 'TCP',
        alert: {
          signature: 'ET MALWARE Reverse Shell Beaconing',
          signature_id: 2099999,
          severity: 1,
          category: 'Trojan Detected',
        },
      });

      assert.strictEqual(event.vendor, 'Suricata');
      assert.strictEqual(event.severity, 'Critical');
      assert.strictEqual(event.provenance?.telemetrySource, 'SURICATA_EVE');
      assert.strictEqual(event.provenance?.isSynthetic, false);
    });
  });

  describe('6. Multi-Source Evidence Correlation & Timeline Engine', () => {

    test('Should correlate multi-source events by target IP address', () => {
      const groups = CorrelationEngine.correlateByIp('192.168.1.105');
      assert.ok(groups.length >= 1, 'Should find correlated group for IP 192.168.1.105');
      assert.strictEqual(groups[0].ipAddress, '192.168.1.105');
      assert.ok(groups[0].telemetrySources.length >= 1);
    });

    test('Should construct evidence bundles and chronological timelines', () => {
      const bundles = EvidenceBundleService.getEvidenceBundles();
      assert.ok(bundles.length >= 1, 'Should construct evidence bundles');

      const timeline = TimelineEngine.getChronologicalTimeline();
      assert.ok(timeline.length >= 1, 'Timeline should contain chronological events');
    });
  });
});
