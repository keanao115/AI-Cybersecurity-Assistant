export interface NmapScanResult {
  host: string;
  os: string;
  openPorts: Array<{
    port: number;
    protocol: string;
    state: string;
    service: string;
    vulns: string;
    rtt?: string;
  }>;
  allResults?: Array<{
    port: number;
    protocol: string;
    state: string;
    service: string;
    vulns: string;
  }>;
}

export function parseNmapTelemetry(rawContent: string): NmapScanResult {
  const openPorts: NmapScanResult['openPorts'] = [];
  let host = "Target Host";
  let os = "Unknown OS / Mixed Telemetry";

  if (rawContent.includes('<nmaprun')) {
    // Basic XML extraction via regex / string matching for high performance
    const hostMatch = rawContent.match(/<address\s+addr="([^"]+)"/);
    if (hostMatch) host = hostMatch[1];

    const osMatch = rawContent.match(/<osmatch\s+name="([^"]+)"/);
    if (osMatch) os = osMatch[1];

    const portRegex = /<port\s+protocol="([^"]+)"\s+portid="([^"]+)">[\s\S]*?<state\s+state="([^"]+)"[\s\S]*?<service\s+name="([^"]+)"(?:[\s\S]*?product="([^"]+)")?(?:[\s\S]*?version="([^"]+)")?[\s\S]*?<\/port>/g;
    let match: RegExpExecArray | null;

    while ((match = portRegex.exec(rawContent)) !== null) {
      const proto = match[1];
      const portId = parseInt(match[2]);
      const state = match[3];
      const serviceName = match[4] || 'unknown';
      const product = match[5] || '';
      const version = match[6] || '';

      const serviceDesc = `${serviceName} ${product} ${version}`.trim();
      const vulns = portId === 445 ? 'MS17-010 SMB Remote Code Execution Risk' :
                    portId === 3389 ? 'BlueKeep RCE / RDP Exposure' :
                    portId === 80 ? 'Cleartext HTTP Protocol Exposure' : 'Normal Service Response';

      openPorts.push({
        port: portId,
        protocol: proto,
        state: state,
        service: serviceDesc,
        vulns: vulns
      });
    }
  } else {
    // Line-by-line standard output parser
    const lines = rawContent.split('\n');
    lines.forEach((line) => {
      if (line.includes('/tcp') || line.includes('/udp')) {
        const parts = line.split(/\s+/).filter(Boolean);
        const [portProto, state] = parts;
        if (portProto && state) {
          const [pNum, proto] = portProto.split('/');
          const serviceName = parts.slice(2).join(' ') || 'Unknown Service';
          openPorts.push({
            port: parseInt(pNum),
            protocol: proto || 'tcp',
            state: state,
            service: serviceName,
            vulns: line.includes('VULNERABLE') ? 'Flagged Vulnerable Service' : 'Active Listener'
          });
        }
      }
    });
  }

  return {
    host,
    os,
    openPorts
  };
}
