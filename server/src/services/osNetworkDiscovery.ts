import { exec } from 'child_process';
import { promisify } from 'util';
import os from 'os';

const execAsync = promisify(exec);

export interface ArpEntry {
  ip: string;
  mac: string;
  type: string;
  interface?: string;
}

export interface NetworkConnection {
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
}

export interface NetworkInterface {
  name: string;
  ipv4: string;
  ipv6?: string;
  mac: string;
  subnet?: string;
  gateway?: string;
}

export interface LocalDiscoveryResult {
  hostname: string;
  platform: string;
  arpEntries: ArpEntry[];
  activeConnections: NetworkConnection[];
  networkInterfaces: NetworkInterface[];
  runAt: string;
}

const isWindows = process.platform === 'win32';

// ─── ARP Table Reader ──────────────────────────────────────────────────────────
export async function getArpTable(): Promise<ArpEntry[]> {
  try {
    const { stdout } = await execAsync(isWindows ? 'arp -a' : 'arp -n');
    return parseArpOutput(stdout);
  } catch {
    return [];
  }
}

function parseArpOutput(raw: string): ArpEntry[] {
  const entries: ArpEntry[] = [];
  const lines = raw.split('\n');

  if (isWindows) {
    // Windows format: "  192.168.1.1     00-11-22-33-44-55     dynamic"
    let currentInterface = '';
    for (const line of lines) {
      const ifaceMatch = line.match(/Interface:\s+([\d.]+)/);
      if (ifaceMatch) { currentInterface = ifaceMatch[1]; continue; }

      const match = line.match(/^\s+([\d.]+)\s+([\w-]+)\s+(\w+)/);
      if (match && match[1] !== '0.0.0.0') {
        entries.push({
          ip: match[1],
          mac: match[2].replace(/-/g, ':').toLowerCase(),
          type: match[3],
          interface: currentInterface,
        });
      }
    }
  } else {
    // Linux format: "hostname (ip) at mac [ether] on iface"
    for (const line of lines) {
      const match = line.match(/\(([\d.]+)\)\s+at\s+([\w:]+)\s+\[(\w+)\]\s+on\s+(\S+)/);
      if (match) {
        entries.push({
          ip: match[1],
          mac: match[2],
          type: match[3],
          interface: match[4],
        });
      }
    }
  }

  return entries;
}

// ─── Active TCP/UDP Connections ────────────────────────────────────────────────
export async function getActiveConnections(): Promise<NetworkConnection[]> {
  try {
    const cmd = isWindows ? 'netstat -an -p tcp' : 'ss -tn';
    const { stdout } = await execAsync(cmd);
    return parseNetstatOutput(stdout);
  } catch {
    return [];
  }
}

function parseNetstatOutput(raw: string): NetworkConnection[] {
  const conns: NetworkConnection[] = [];
  const lines = raw.split('\n');

  for (const line of lines) {
    if (isWindows) {
      // TCP    0.0.0.0:80     0.0.0.0:0     LISTENING
      const match = line.match(/^\s+(TCP|UDP)\s+([\d.*:]+):(\d+)\s+([\d.*:]+):(\d+)\s+(\w+)/i);
      if (match) {
        conns.push({
          protocol: match[1].toUpperCase(),
          localAddress: match[2],
          localPort: parseInt(match[3]),
          remoteAddress: match[4],
          remotePort: parseInt(match[5]),
          state: match[6],
        });
      }
    } else {
      // ESTAB 0 0 192.168.1.100:54321 8.8.8.8:443
      const match = line.match(/^(\w+)\s+\d+\s+\d+\s+([\d.]+):(\d+)\s+([\d.]+):(\d+)/);
      if (match) {
        conns.push({
          protocol: 'TCP',
          localAddress: match[2],
          localPort: parseInt(match[3]),
          remoteAddress: match[4],
          remotePort: parseInt(match[5]),
          state: match[1],
        });
      }
    }
  }

  return conns.slice(0, 100); // Limit to top 100
}

// ─── Network Interfaces ────────────────────────────────────────────────────────
export function getLocalNetworkInterfaces(): NetworkInterface[] {
  const ifaces = os.networkInterfaces();
  const results: NetworkInterface[] = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    const ipv4 = addrs.find(a => a.family === 'IPv4' && !a.internal);
    const ipv6 = addrs.find(a => a.family === 'IPv6' && !a.internal);
    if (ipv4) {
      results.push({
        name,
        ipv4: ipv4.address,
        ipv6: ipv6?.address,
        mac: ipv4.mac || 'unknown',
        subnet: ipv4.netmask,
      });
    }
  }

  return results;
}

// ─── Combined Local Discovery ──────────────────────────────────────────────────
export async function runLocalNetworkDiscovery(): Promise<LocalDiscoveryResult> {
  const [arpEntries, activeConnections] = await Promise.all([
    getArpTable(),
    getActiveConnections(),
  ]);

  return {
    hostname: os.hostname(),
    platform: process.platform,
    arpEntries,
    activeConnections,
    networkInterfaces: getLocalNetworkInterfaces(),
    runAt: new Date().toISOString(),
  };
}

// ─── Build DiscoveredAsset list from real OS data ─────────────────────────────
export async function buildRealAssetList() {
  const discovery = await runLocalNetworkDiscovery();
  const assets: any[] = [];

  // Add the local machine itself
  const localIfaces = discovery.networkInterfaces;
  if (localIfaces.length > 0) {
    assets.push({
      hostname: discovery.hostname,
      ip_address: localIfaces[0].ipv4,
      mac_address: localIfaces[0].mac,
      os_name: `${process.platform} (Node ${process.version})`,
      status: 'Active',
      installed_software: [],
      running_services: discovery.activeConnections
        .filter(c => c.state === 'LISTENING' || c.state === 'LISTEN')
        .slice(0, 10)
        .map(c => ({ port: c.localPort, service: `${c.protocol.toLowerCase()}:${c.localPort}` })),
      owner: 'Local System',
      tags: ['Localhost', 'SOC Platform Host'],
      vulnerabilityCount: 0,
      lastDiscoveredAt: new Date().toISOString(),
      source: 'os_discovery',
    });
  }

  // Add devices from ARP table
  for (const arp of discovery.arpEntries.slice(0, 20)) {
    if (arp.mac === 'ff:ff:ff:ff:ff:ff' || arp.type === 'invalid') continue;
    assets.push({
      hostname: `host-${arp.ip.replace(/\./g, '-')}`,
      ip_address: arp.ip,
      mac_address: arp.mac,
      os_name: 'Unknown (ARP Discovery)',
      status: 'Active',
      installed_software: [],
      running_services: [],
      owner: 'Discovered via ARP',
      tags: ['Network Device', arp.type === 'dynamic' ? 'DHCP' : 'Static'],
      vulnerabilityCount: 0,
      lastDiscoveredAt: new Date().toISOString(),
      source: 'arp_table',
    });
  }

  return {
    assets,
    rawDiscovery: discovery,
  };
}
