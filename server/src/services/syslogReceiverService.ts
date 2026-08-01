// Real Syslog UDP Receiver — RFC 3164 / RFC 5424
// Listens on UDP port 5514 (non-privileged alternative to 514)
// Parses syslog messages and feeds them into the SIEM ingest pipeline

import dgram from 'dgram';
import { ingestSiemEvent, SiemSourceCategory } from './siemCollectorService.js';
import { broadcastTelemetryEvent } from './websocketService.js';

export interface ParsedSyslogMessage {
  facility: number;
  severity: number;
  severityLabel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  timestamp: string;
  hostname: string;
  tag: string;
  message: string;
  sourceIp: string;
  raw: string;
}

const SYSLOG_PORT = parseInt(process.env.SYSLOG_PORT || '5514');

let udpServer: dgram.Socket | null = null;
let messagesReceived = 0;

// Syslog severity → SOC severity mapping
function mapSyslogSeverity(sev: number): 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' {
  if (sev <= 1) return 'Critical'; // 0=Emergency, 1=Alert
  if (sev === 2) return 'Critical'; // Critical
  if (sev === 3) return 'High';     // Error
  if (sev === 4) return 'Medium';   // Warning
  if (sev === 5) return 'Medium';   // Notice
  if (sev === 6) return 'Low';      // Informational
  return 'Info';                    // Debug
}

// RFC 3164: <priority>timestamp hostname tag: message
// RFC 5424: <priority>version timestamp hostname app-name procid msgid ...
function parseSyslogMessage(raw: string, sourceIp: string): ParsedSyslogMessage | null {
  try {
    const priorityMatch = raw.match(/^<(\d+)>/);
    if (!priorityMatch) return null;

    const priority = parseInt(priorityMatch[1]);
    const facility = Math.floor(priority / 8);
    const severity = priority % 8;
    const rest = raw.slice(priorityMatch[0].length);

    // RFC 5424 detection: starts with version number
    const is5424 = /^\d+ /.test(rest);

    let timestamp = new Date().toISOString();
    let hostname = sourceIp;
    let tag = 'syslog';
    let message = rest;

    if (is5424) {
      // <priority>version timestamp hostname app-name procid msgid ...
      const parts = rest.split(' ');
      if (parts.length >= 7) {
        if (parts[1] !== '-') timestamp = new Date(parts[1]).toISOString();
        if (parts[2] !== '-') hostname = parts[2];
        if (parts[3] !== '-') tag = parts[3];
        message = parts.slice(6).join(' ').replace(/^-\s*/, '');
      }
    } else {
      // RFC 3164: "Jan  1 12:00:00 hostname tag: message"
      const rfc3164 = rest.match(/^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)/);
      if (rfc3164) {
        timestamp = new Date(`${rfc3164[1]} ${new Date().getFullYear()}`).toISOString();
        hostname = rfc3164[2];
        tag = rfc3164[3];
        message = rfc3164[4];
      }
    }

    return {
      facility,
      severity,
      severityLabel: mapSyslogSeverity(severity),
      timestamp,
      hostname,
      tag,
      message,
      sourceIp,
      raw,
    };
  } catch {
    return null;
  }
}

// Map syslog tag/app to SIEM source category
function inferSourceCategory(tag: string, message: string): SiemSourceCategory {
  const t = `${tag} ${message}`.toLowerCase();
  if (t.includes('sshd') || t.includes('ssh')) return 'Linux_Auditd';
  if (t.includes('sudo')) return 'Linux_Auditd';
  if (t.includes('kernel') || t.includes('audit')) return 'Linux_Auditd';
  if (t.includes('firewall') || t.includes('panos') || t.includes('asa')) return 'Firewall';
  if (t.includes('suricata') || t.includes('snort')) return 'Suricata';
  if (t.includes('zeek') || t.includes('bro')) return 'Zeek';
  if (t.includes('vpn') || t.includes('anyconnect') || t.includes('openvpn')) return 'VPN_Gateway';
  if (t.includes('wazuh')) return 'Wazuh';
  if (t.includes('crowdstrike') || t.includes('falcon')) return 'CrowdStrike';
  if (t.includes('switch') || t.includes('router') || t.includes('cisco ios')) return 'Switch_Router';
  return 'Linux_Auditd';
}

export function startSyslogReceiver(): void {
  if (udpServer) return;

  udpServer = dgram.createSocket('udp4');

  udpServer.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
    const raw = msg.toString('utf8');
    const parsed = parseSyslogMessage(raw, rinfo.address);

    if (!parsed) return;
    messagesReceived++;

    const sourceCategory = inferSourceCategory(parsed.tag, parsed.message);

    // Feed into SIEM pipeline
    const siemEvent = ingestSiemEvent({
      sourceCategory,
      hostName: parsed.hostname || rinfo.address,
      severity: parsed.severityLabel === 'Info' ? 'Low' : parsed.severityLabel,
      eventId: `SYSLOG-${parsed.tag.toUpperCase()}`,
      mitreTechnique: '',
      summary: `${parsed.tag}: ${parsed.message.substring(0, 200)}`,
      rawDetails: {
        facility: parsed.facility,
        syslogSeverity: parsed.severity,
        sourceIp: rinfo.address,
        port: rinfo.port,
        tag: parsed.tag,
        raw: parsed.raw.substring(0, 500),
      },
    });

    // Broadcast immediately over WebSocket
    broadcastTelemetryEvent({
      type: 'SYSLOG_RECEIVED',
      event: siemEvent,
      sourceIp: rinfo.address,
      timestamp: new Date().toISOString(),
    });

    if (messagesReceived <= 5 || messagesReceived % 100 === 0) {
      console.log(`[Syslog] Received #${messagesReceived} from ${rinfo.address}:${rinfo.port} — ${parsed.tag}: ${parsed.message.substring(0, 60)}`);
    }
  });

  udpServer.on('error', (err: Error) => {
    console.error('[Syslog] UDP server error:', err.message);
    udpServer?.close();
    udpServer = null;
  });

  udpServer.bind(SYSLOG_PORT, () => {
    console.log(`[Syslog] UDP receiver active on port ${SYSLOG_PORT} (RFC 3164/5424). Send events: logger -n localhost -P ${SYSLOG_PORT} "test message"`);
  });
}

export function getSyslogStats() {
  return {
    active: udpServer !== null,
    port: SYSLOG_PORT,
    messagesReceived,
    protocol: 'UDP',
    standards: ['RFC 3164', 'RFC 5424'],
  };
}

export function stopSyslogReceiver(): void {
  if (udpServer) {
    udpServer.close();
    udpServer = null;
  }
}
