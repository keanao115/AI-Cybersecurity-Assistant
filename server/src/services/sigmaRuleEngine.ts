// Sigma Detection Rule Engine — Pure TypeScript, no external YAML deps
// Built-in Sigma-inspired detection rules for common SOC threats
// Applied automatically to every log event ingested via /api/ingest/logs

export interface SigmaRule {
  id: string;
  title: string;
  status: 'production' | 'test' | 'experimental';
  level: 'critical' | 'high' | 'medium' | 'low';
  mitre: string[];
  description: string;
  match: (event: any) => boolean;
  response: string;
}

// ─── Built-in Detection Rules ─────────────────────────────────────────────────
export const SIGMA_RULES: SigmaRule[] = [
  {
    id: 'SOC-001',
    title: 'Windows Brute Force — Multiple Failed Logons (4625)',
    status: 'production',
    level: 'high',
    mitre: ['T1110.001'],
    description: 'Detects high-volume failed logon attempts (Event ID 4625) indicative of password spraying or brute force.',
    match: (e) =>
      (e.eventId === '4625' || e.commandLine?.includes('4625')) &&
      (e.sourceType?.includes('Windows') || e.logType === 'windows'),
    response: 'Enable account lockout policy. Block source IP at perimeter. Review VPN and OWA access logs.',
  },
  {
    id: 'SOC-002',
    title: 'Suspicious Process Creation — Encoded PowerShell (4688)',
    status: 'production',
    level: 'critical',
    mitre: ['T1059.001', 'T1027'],
    description: 'Detects PowerShell with -EncodedCommand or -enc flag, used by Cobalt Strike, Empire, and other frameworks.',
    match: (e) =>
      (e.eventId === '4688' || e.commandLine?.includes('4688')) &&
      (e.commandLine?.toLowerCase().includes('-enc') ||
        e.commandLine?.toLowerCase().includes('-encodedcommand') ||
        e.commandLine?.toLowerCase().includes('iex') ||
        e.commandLine?.toLowerCase().includes('invoke-expression')),
    response: 'Isolate endpoint. Decode Base64 payload. Block PowerShell execution via AppLocker. Enable Script Block Logging (4104).',
  },
  {
    id: 'SOC-003',
    title: 'Audit Log Cleared (Event ID 1102)',
    status: 'production',
    level: 'critical',
    mitre: ['T1070.001'],
    description: 'Windows Security audit log was cleared — strong indicator of attacker covering tracks.',
    match: (e) =>
      e.eventId === '1102' ||
      e.commandLine?.includes('1102') ||
      e.details?.toLowerCase().includes('audit log') ||
      e.details?.toLowerCase().includes('log cleared'),
    response: 'Immediately escalate to Tier 3. Preserve memory image. Check for WevtUtil clear-log. Review preceding 4625/4688 events.',
  },
  {
    id: 'SOC-004',
    title: 'New Local User Account Created (Event ID 4720)',
    status: 'production',
    level: 'high',
    mitre: ['T1136.001'],
    description: 'A new local user account was created. Could indicate persistence via backdoor accounts.',
    match: (e) =>
      e.eventId === '4720' ||
      e.commandLine?.includes('4720') ||
      e.details?.toLowerCase().includes('user account created'),
    response: 'Verify account creation was authorized. Remove unauthorized accounts. Review group membership (4728).',
  },
  {
    id: 'SOC-005',
    title: 'Sudo Privilege Escalation — Linux',
    status: 'production',
    level: 'high',
    mitre: ['T1548.003'],
    description: 'Sudo command execution detected on Linux host. Especially suspicious when piped with curl/wget.',
    match: (e) =>
      e.sourceType?.toLowerCase().includes('linux') &&
      (e.commandLine?.includes('sudo') || e.details?.includes('sudo')) &&
      (e.commandLine?.includes('curl') || e.commandLine?.includes('wget') ||
        e.commandLine?.includes('bash -c') || e.commandLine?.includes('sh -c')),
    response: 'Review /var/log/auth.log. Check crontab -l for persistence. Audit /etc/sudoers modifications.',
  },
  {
    id: 'SOC-006',
    title: 'SSH Brute Force — Linux Auth Log',
    status: 'production',
    level: 'high',
    mitre: ['T1110.001'],
    description: 'Multiple SSH authentication failures from a single source IP.',
    match: (e) =>
      (e.sourceType?.toLowerCase().includes('linux') || e.raw?.includes('sshd')) &&
      (e.details?.toLowerCase().includes('failed password') ||
        e.details?.toLowerCase().includes('invalid user') ||
        e.raw?.toLowerCase().includes('failed password')),
    response: 'Implement fail2ban or UFW rate-limiting. Block attacker IPs. Enforce SSH key-only authentication.',
  },
  {
    id: 'SOC-007',
    title: 'Suricata — Malware C2 Traffic Detected',
    status: 'production',
    level: 'critical',
    mitre: ['T1071.001', 'T1071.004'],
    description: 'Suricata IDS detected outbound malware C2 communication.',
    match: (e) =>
      e.sourceType?.includes('Suricata') &&
      (e.alert?.severity === 1 ||
        e.alert?.category?.toLowerCase().includes('malware') ||
        e.details?.toLowerCase().includes('et malware') ||
        e.details?.toLowerCase().includes('c2')),
    response: 'Block destination IP at perimeter immediately. Isolate source host. Run EDR full disk scan.',
  },
  {
    id: 'SOC-008',
    title: 'Nmap — Vulnerable Service Discovered',
    status: 'production',
    level: 'high',
    mitre: ['T1046'],
    description: 'Nmap scan identified an open port associated with a known vulnerability (SMB 445, RDP 3389, Telnet 23).',
    match: (e) =>
      e.sourceType?.includes('Nmap') &&
      (e.vulns?.includes('EternalBlue') || e.vulns?.includes('BlueKeep') ||
        e.vulns?.includes('Insecure') || e.state === 'open'),
    response: 'Apply MS17-010 patch. Disable SMBv1. Enable NLA for RDP. Block Telnet at firewall.',
  },
  {
    id: 'SOC-009',
    title: 'Lateral Movement — WMI / PsExec Process Execution',
    status: 'production',
    level: 'critical',
    mitre: ['T1021.003', 'T1570'],
    description: 'WMI or PsExec used to remotely execute a process — common lateral movement technique.',
    match: (e) =>
      (e.commandLine?.toLowerCase().includes('wmic') ||
        e.commandLine?.toLowerCase().includes('psexec') ||
        e.commandLine?.toLowerCase().includes('wmiexec') ||
        e.process?.toLowerCase().includes('wmiprvse')),
    response: 'Block PsExec via AppLocker. Restrict WMI namespaces. Enable WDAC. Hunt for parent-child chains.',
  },
  {
    id: 'SOC-010',
    title: 'Credential Dump — LSASS Access (Mimikatz Pattern)',
    status: 'production',
    level: 'critical',
    mitre: ['T1003.001'],
    description: 'Process access to LSASS memory — classic Mimikatz or credential dumping behavior.',
    match: (e) =>
      e.commandLine?.toLowerCase().includes('lsass') ||
      e.commandLine?.toLowerCase().includes('sekurlsa') ||
      e.commandLine?.toLowerCase().includes('mimikatz') ||
      e.details?.toLowerCase().includes('lsass'),
    response: 'Enable Credential Guard. Enable Protected Process Light for LSASS. Block with Windows Defender Attack Surface Reduction rules.',
  },
];

export interface SigmaMatchResult {
  ruleId: string;
  ruleTitle: string;
  level: 'critical' | 'high' | 'medium' | 'low';
  mitre: string[];
  description: string;
  response: string;
  matchedEventId: string;
}

// ─── Evaluate All Rules Against a Single Event ────────────────────────────────
export function evaluateSigmaRules(event: any): SigmaMatchResult[] {
  const matches: SigmaMatchResult[] = [];

  for (const rule of SIGMA_RULES) {
    try {
      if (rule.match(event)) {
        matches.push({
          ruleId: rule.id,
          ruleTitle: rule.title,
          level: rule.level,
          mitre: rule.mitre,
          description: rule.description,
          response: rule.response,
          matchedEventId: event.id || event.eventId || 'unknown',
        });
      }
    } catch {
      // Skip rules that throw on malformed events
    }
  }

  return matches;
}

// ─── Batch Evaluate Against All Events ───────────────────────────────────────
export function scanWithSigmaRules(events: any[]): {
  totalEvents: number;
  matchedEvents: number;
  totalDetections: number;
  detections: Array<{ event: any; matches: SigmaMatchResult[] }>;
  summary: Record<string, number>;
} {
  const detections: Array<{ event: any; matches: SigmaMatchResult[] }> = [];
  const summary: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const event of events) {
    const matches = evaluateSigmaRules(event);
    if (matches.length > 0) {
      detections.push({ event, matches });
      for (const m of matches) summary[m.level] = (summary[m.level] || 0) + 1;
    }
  }

  return {
    totalEvents: events.length,
    matchedEvents: detections.length,
    totalDetections: detections.reduce((acc, d) => acc + d.matches.length, 0),
    detections,
    summary,
  };
}

export function getSigmaRuleList() {
  return SIGMA_RULES.map(r => ({
    id: r.id, title: r.title, status: r.status,
    level: r.level, mitre: r.mitre, description: r.description,
  }));
}
