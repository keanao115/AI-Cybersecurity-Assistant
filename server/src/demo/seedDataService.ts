import { memoryDb } from '../db/client.js';
import { loadPlatformConfig } from '../config/platformConfig.js';
import { createSeededDemoProvenance } from '../provenance/provenanceFactory.js';

export function seedDemoData(): void {
  const config = loadPlatformConfig();
  if (!config.enableSeedData || config.platformMode !== 'DEMO') {
    return;
  }

  // Check if seeded assets already exist
  const existingSeeded = memoryDb.assets.filter((a) => a.provenance?.isSeeded);
  if (existingSeeded.length > 0) return;

  const provenance = createSeededDemoProvenance('asset-seed');

  const demoAssets = [
    {
      id: 1,
      hostname: 'DC-SRV-01.corp.internal',
      ip_address: '192.168.1.10',
      mac_address: '00:15:5D:01:2A:8C',
      os_name: 'Windows Server 2022 Datacenter',
      status: 'Active',
      installed_software: [{ name: 'Apache httpd', version: '2.4.49' }, { name: 'OpenSSH', version: '8.2p1' }],
      running_services: [{ port: 80, service: 'http' }, { port: 445, service: 'microsoft-ds' }],
      owner: 'Domain Controller Admin',
      tags: ['Critical', 'DC', 'Internal'],
      provenance,
    },
    {
      id: 2,
      hostname: 'web-prod-01.corp.internal',
      ip_address: '192.168.1.50',
      mac_address: '00:15:5D:04:3B:11',
      os_name: 'Ubuntu 22.04 LTS (Linux kernel 5.15)',
      status: 'Active',
      installed_software: [{ name: 'Log4j', version: '2.14.1' }, { name: 'nginx', version: '1.18.0' }],
      running_services: [{ port: 443, service: 'https' }, { port: 8080, service: 'http-proxy' }],
      owner: 'DevOps / Cloud Team',
      tags: ['Web', 'DMZ', 'Production'],
      provenance,
    },
  ];

  memoryDb.assets.push(...demoAssets);
  console.log('[Seed Data Service] Seeded 2 demo asset records with SEEDED_DEMO provenance.');
}

export function clearDemoData(): number {
  const initialLen = memoryDb.assets.length;

  // Filter out seeded demo assets
  memoryDb.assets = memoryDb.assets.filter((a) => !a.provenance?.isSeeded);
  memoryDb.unifiedEvents = memoryDb.unifiedEvents.filter((e) => !e.provenance?.isSynthetic && !e.provenance?.isSeeded);

  const removedCount = initialLen - memoryDb.assets.length;
  console.log(`[Seed Data Service] Cleared ${removedCount} demo records without affecting live data.`);
  return removedCount;
}
