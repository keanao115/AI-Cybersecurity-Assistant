// RFC 3164 and RFC 5424 Standard Syslog Decoders

export interface ParsedSyslogRfc {
  pri: number;
  facility: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  severityCode: number;
  facilityCode: number;
  version?: number;
  timestamp: string;
  hostname: string;
  appName: string;
  procId: string;
  msgId?: string;
  structuredData?: string;
  message: string;
  isRfc5424: boolean;
}

const FACILITIES: string[] = [
  'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'printer', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'logaudit', 'logalert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
];

const SEVERITIES: Array<'Critical' | 'High' | 'Medium' | 'Low' | 'Info'> = [
  'Critical', // 0: Emergency
  'Critical', // 1: Alert
  'Critical', // 2: Critical
  'High',     // 3: Error
  'Medium',   // 4: Warning
  'Low',      // 5: Notice
  'Info',     // 6: Informational
  'Info',     // 7: Debug
];

export function parseSyslogHeader(rawMsg: string): ParsedSyslogRfc {
  let text = rawMsg.trim();

  // Extract PRI (<num>)
  let pri = 13; // Default user.notice
  const priMatch = text.match(/^<(\d{1,3})>/);
  if (priMatch) {
    pri = parseInt(priMatch[1], 10);
    text = text.substring(priMatch[0].length).trim();
  }

  const facilityCode = Math.floor(pri / 8);
  const severityCode = pri % 8;
  const facility = FACILITIES[facilityCode] || `facility-${facilityCode}`;
  const severity = SEVERITIES[severityCode] || 'Info';

  // Check RFC 5424 (starts with version number, e.g., "1 ")
  const rfc5424Match = text.match(/^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:(\[.*?\])|-)?\s*(.*)$/);

  if (rfc5424Match) {
    const [, timestamp, hostname, appName, procId, msgId, structuredData, message] = rfc5424Match;
    return {
      pri,
      facility,
      severity,
      facilityCode,
      severityCode,
      version: 1,
      timestamp: parseSyslogTimestamp(timestamp),
      hostname: hostname !== '-' ? hostname : 'unknown-host',
      appName: appName !== '-' ? appName : 'syslog',
      procId: procId !== '-' ? procId : '',
      msgId: msgId !== '-' ? msgId : undefined,
      structuredData: structuredData && structuredData !== '-' ? structuredData : undefined,
      message: message || '',
      isRfc5424: true,
    };
  }

  // Fallback RFC 3164 (<PRI>MMM DD HH:MM:SS HOST TAG[PID]: MSG)
  const rfc3164Match = text.match(/^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$/);

  if (rfc3164Match) {
    const [, timestamp, hostname, appName, procId, message] = rfc3164Match;
    return {
      pri,
      facility,
      severity,
      facilityCode,
      severityCode,
      timestamp: parseSyslogTimestamp(timestamp),
      hostname,
      appName,
      procId: procId || '',
      message: message || '',
      isRfc5424: false,
    };
  }

  // Loose Fallback Parser for non-compliant network logs
  const parts = text.split(/\s+/);
  return {
    pri,
    facility,
    severity,
    facilityCode,
    severityCode,
    timestamp: new Date().toISOString(),
    hostname: parts[0] || 'unknown-host',
    appName: 'syslog-generic',
    procId: '',
    message: text,
    isRfc5424: false,
  };
}

function parseSyslogTimestamp(tsStr: string): string {
  if (!tsStr) return new Date().toISOString();
  try {
    const parsed = new Date(tsStr);
    if (!isNaN(parsed.getTime())) return parsed.toISOString();
  } catch {}

  // Handle RFC 3164 BSD timestamp without year (e.g. "Jul 31 18:00:00")
  try {
    const currentYear = new Date().getFullYear();
    const parsedBsd = new Date(`${tsStr} ${currentYear}`);
    if (!isNaN(parsedBsd.getTime())) return parsedBsd.toISOString();
  } catch {}

  return new Date().toISOString();
}
