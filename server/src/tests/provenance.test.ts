import assert from 'assert';
import { test, describe } from 'node:test';
import { loadPlatformConfig, updatePlatformConfigOverride } from '../config/platformConfig.js';
import {
  createLiveCollectorProvenance,
  createSyntheticDemoProvenance,
  createPcapUploadProvenance,
} from '../provenance/provenanceFactory.js';
import { SyntheticFlowGenerator } from '../demo/syntheticFlowGenerator.js';
import { getLiveNetworkFlows, ingestNetFlowRecord } from '../services/networkFlowService.js';

describe('Operating Modes & Telemetry Provenance Suite', () => {

  describe('1. Centralized Platform Configuration Defaults', () => {
    test('Default mode must strictly be LIVE when unconfigured', () => {
      delete process.env.PLATFORM_MODE;
      const config = loadPlatformConfig();
      assert.strictEqual(config.platformMode, 'LIVE');
      assert.strictEqual(config.enableSyntheticData, false);
      assert.strictEqual(config.enableSeedData, false);
    });

    test('Invalid PLATFORM_MODE string safely defaults to LIVE', () => {
      process.env.PLATFORM_MODE = 'INVALID_MODE_STRING';
      const config = loadPlatformConfig();
      assert.strictEqual(config.platformMode, 'LIVE');
      assert.strictEqual(config.enableSyntheticData, false);
    });
  });

  describe('2. Telemetry Provenance Factory Builders', () => {
    test('Live Syslog Collector Provenance Builder', () => {
      const prov = createLiveCollectorProvenance('syslog', 'syslog-udp-5514');
      assert.strictEqual(prov.telemetrySource, 'SYSLOG_COLLECTOR');
      assert.strictEqual(prov.collectionMethod, 'NETWORK_RECEIVER');
      assert.strictEqual(prov.isSynthetic, false);
      assert.strictEqual(prov.isSeeded, false);
      assert.strictEqual(prov.collectorId, 'syslog-udp-5514');
    });

    test('PCAP Binary Upload Provenance Builder', () => {
      const prov = createPcapUploadProvenance('capture.pcap', 'PCAP-101');
      assert.strictEqual(prov.telemetrySource, 'PCAP_UPLOAD');
      assert.strictEqual(prov.collectionMethod, 'FILE_UPLOAD');
      assert.strictEqual(prov.isSynthetic, false);
      assert.strictEqual(prov.originalFileName, 'capture.pcap');
      assert.strictEqual(prov.ingestionSessionId, 'PCAP-101');
    });

    test('Synthetic Demonstration Provenance Builder', () => {
      const prov = createSyntheticDemoProvenance('test-scenario');
      assert.strictEqual(prov.telemetrySource, 'SYNTHETIC_DEMO');
      assert.strictEqual(prov.collectionMethod, 'SIMULATION');
      assert.strictEqual(prov.isSynthetic, true);
      assert.strictEqual(prov.isSeeded, false);
    });
  });

  describe('3. Synthetic Generator Security Guards', () => {
    test('Synthetic generator must be BLOCKED from starting in LIVE mode', () => {
      updatePlatformConfigOverride({ platformMode: 'LIVE', enableSyntheticData: false });
      const generator = SyntheticFlowGenerator.getInstance();
      const started = generator.start();

      assert.strictEqual(started, false);
      assert.strictEqual(generator.getStatus().isRunning, false);
    });

    test('Synthetic generator starts only when PLATFORM_MODE=DEMO and enableSyntheticData=true', () => {
      updatePlatformConfigOverride({ platformMode: 'DEMO', enableSyntheticData: true });
      const generator = SyntheticFlowGenerator.getInstance();
      const started = generator.start();

      assert.strictEqual(started, true);
      assert.strictEqual(generator.getStatus().isRunning, true);

      // Clean up
      generator.stop();
      updatePlatformConfigOverride({ platformMode: 'LIVE', enableSyntheticData: false });
    });
  });

  describe('4. Telemetry Source Data Isolation', () => {
    test('LIVE mode queries must exclude synthetic records', () => {
      updatePlatformConfigOverride({ platformMode: 'LIVE', enableSyntheticData: false });

      // Ingest 1 genuine flow and 1 synthetic flow
      ingestNetFlowRecord({
        sourceType: 'NetFlow_v9',
        srcIp: '10.0.0.1',
        srcPort: 54321,
        destIp: '10.0.0.2',
        destPort: 80,
        protocol: 'TCP',
        bytes: 1000,
        packets: 10,
        durationMs: 100,
        direction: 'INBOUND',
        vlanId: 1,
        geoCountry: 'INTERNAL',
        provenance: createLiveCollectorProvenance('netflow', 'netflow-udp-2055'),
      });

      ingestNetFlowRecord({
        sourceType: 'IPFIX',
        srcIp: '192.168.1.99',
        srcPort: 4444,
        destIp: '192.168.1.1',
        destPort: 80,
        protocol: 'TCP',
        bytes: 500,
        packets: 5,
        durationMs: 50,
        direction: 'LATERAL',
        vlanId: 1,
        geoCountry: 'INTERNAL',
        provenance: createSyntheticDemoProvenance('test'),
      });

      const liveFlows = getLiveNetworkFlows({ includeSynthetic: false });
      const hasSynthetic = liveFlows.some((f) => f.provenance?.isSynthetic);

      assert.strictEqual(hasSynthetic, false);
    });
  });
});
