import React, { useState } from 'react';
import { Grid, ShieldAlert, CheckCircle, Info, Zap, Terminal, Activity, FileCode, Server } from 'lucide-react';

const TACTICS_DATA = [
  {
    name: 'Reconnaissance',
    techniques: [
      {
        id: 'T1595',
        name: 'Active Scanning',
        tactic: 'Reconnaissance',
        ports: [80, 443, 3389, 445, 22, 21, 53, 8080],
        description: 'Adversaries execute automated TCP SYN/Connect port scans or vulnerability probing against host IP ranges to identify active network services and vulnerable listening daemons.',
        logSources: 'Network Firewall Logs, Router NetFlow, IDS/IPS TCP Handshake Telemetry',
        mitigation: 'Implement Rate-Limiting, Deploy Web Application Firewall (WAF), block scanning IP ranges.',
        detectionRule: 'Sigma: Selection port_scan_threshold > 50 connections/min'
      },
      {
        id: 'T1592',
        name: 'Gather Host Info',
        tactic: 'Reconnaissance',
        ports: [80, 443, 8080],
        description: 'Adversaries collect details about target host system architecture, operating system kernel build, active software banner headers, and hostname structures.',
        logSources: 'Web Server Access Logs, Banner Grabbing Telemetry, DNS Queries',
        mitigation: 'Disable verbose HTTP Server response headers (e.g. Server: Apache/2.4.41).',
        detectionRule: 'Sigma: HTTP Request User-Agent contains Nmap / Masscan / Nikto'
      }
    ]
  },
  {
    name: 'Initial Access',
    techniques: [
      {
        id: 'T1190',
        name: 'Exploit Public App',
        tactic: 'Initial Access',
        ports: [80, 443, 8080, 8443],
        description: 'Adversaries exploit software vulnerabilities, unpatched CVEs, or input parameter flaws (SQLi, RCE, Log4Shell) in public-facing web applications.',
        logSources: 'Nginx / Apache HTTP Access Logs, WAF Interception Audit Logs',
        mitigation: 'Apply patch management SLAs, enforce input sanitization, enable ModSecurity WAF rules.',
        detectionRule: 'Snort: alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"SQLi Attempt";)'
      },
      {
        id: 'T1566',
        name: 'Phishing',
        tactic: 'Initial Access',
        ports: [25, 587, 993],
        description: 'Adversaries send spear-phishing emails containing malicious document attachments or credential harvesting links to obtain initial execution on internal endpoints.',
        logSources: 'Email Gateway Logs, Attachment Sandbox Reports, Mail Server Audit',
        mitigation: 'Enforce SPF/DKIM/DMARC policies, block dangerous email attachment extensions (.exe, .vbs, .ps1).',
        detectionRule: 'Yara: rule Phishing_Macro_Doc { strings: $a = "AutoOpen" condition: $a }'
      }
    ]
  },
  {
    name: 'Execution',
    techniques: [
      {
        id: 'T1059.001',
        name: 'PowerShell Stager',
        tactic: 'Execution',
        ports: [],
        description: 'Adversaries abuse powershell.exe command-line interpreter to run Base64 encoded stagers, download secondary payloads, or perform in-memory DLL injection.',
        logSources: 'Windows Security Event ID 4688, PowerShell Script Block Logging Event ID 4104',
        mitigation: 'Enforce Constrained Language Mode, require AppLocker / WDAC binary code signing.',
        detectionRule: 'Sigma: CommandLine contains "-ExecutionPolicy Bypass" or "-enc"'
      },
      {
        id: 'T1059.003',
        name: 'Windows Cmd Execution',
        tactic: 'Execution',
        ports: [],
        description: 'Adversaries leverage command prompt cmd.exe to launch system discovery commands, batch scripts, or process spawned by malicious Office macros.',
        logSources: 'Windows Event ID 4688 Process Creation with Command-Line Auditing',
        mitigation: 'Restrict non-administrative access to cmd.exe via Group Policy Object (GPO).',
        detectionRule: 'Sigma: ParentImage endswith "\\winword.exe" and Image endswith "\\cmd.exe"'
      }
    ]
  },
  {
    name: 'Persistence',
    techniques: [
      {
        id: 'T1136.001',
        name: 'Create Local Account',
        tactic: 'Persistence',
        ports: [],
        description: 'Adversaries create covert local administrative accounts (e.g. shadow_admin) to maintain persistent access after initial compromise.',
        logSources: 'Windows Security Event ID 4720 (User Account Created), Event ID 4732 (Group Membership Added)',
        mitigation: 'Enforce LAPS (Local Administrator Password Solution), audit local group memberships.',
        detectionRule: 'Sigma: EventID: 4720 and TargetUserName not in Authorized_Provisioning_List'
      },
      {
        id: 'T1053',
        name: 'Scheduled Task',
        tactic: 'Persistence',
        ports: [],
        description: 'Adversaries abuse Windows Task Scheduler (schtasks.exe) or Linux cron daemon to trigger recurring malicious execution upon system boot or fixed schedules.',
        logSources: 'Windows TaskScheduler Event ID 4698, Linux Auditd /var/log/cron',
        mitigation: 'Restrict task creation privileges to System Administrators, monitor C:\\Windows\\System32\\Tasks.',
        detectionRule: 'Sigma: EventID: 4698 and TaskName contains "\\AppData\\Local\\Temp"'
      }
    ]
  },
  {
    name: 'Privilege Escalation',
    techniques: [
      {
        id: 'T1548.003',
        name: 'Sudo & Privilege Abuse',
        tactic: 'Privilege Escalation',
        ports: [22],
        description: 'Adversaries exploit misconfigured /etc/sudoers rules or NOPASSWD directives to escalate privileges from unprivileged user to root.',
        logSources: 'Linux Syslog /var/log/auth.log, Auditd SYSCALL records',
        mitigation: 'Enforce strict sudoers configuration without NOPASSWD wildcards.',
        detectionRule: 'Sigma: Syslog message contains "COMMAND=/bin/bash" or "COMMAND=/usr/bin/python"'
      },
      {
        id: 'T1068',
        name: 'Exploit Vulnerability',
        tactic: 'Privilege Escalation',
        ports: [445, 139],
        description: 'Adversaries execute local privilege escalation (LPE) exploits targeting unpatched OS kernel vulnerabilities to gain SYSTEM or root access.',
        logSources: 'Windows System Event Log, Kernel Exception Dumps, EDR Telemetry',
        mitigation: 'Deploy monthly OS kernel security updates and CVE patches.',
        detectionRule: 'Sigma: Process creation by SYSTEM user originating from temp folder'
      }
    ]
  },
  {
    name: 'Defense Evasion',
    techniques: [
      {
        id: 'T1070.001',
        name: 'Clear Event Logs',
        tactic: 'Defense Evasion',
        ports: [],
        description: 'Adversaries execute wevtutil.exe cl Security or PowerShell commands to purge Windows Event Logs and erase forensic traces of intrusion.',
        logSources: 'Windows Security Event ID 1102 (The audit log was cleared)',
        mitigation: 'Stream Event Logs immediately to an offsite immutable SIEM collector.',
        detectionRule: 'Sigma: EventID: 1102 or CommandLine contains "wevtutil cl"'
      },
      {
        id: 'T1027',
        name: 'Obfuscated Files',
        tactic: 'Defense Evasion',
        ports: [],
        description: 'Adversaries compress, encrypt, or Base64 encode script payloads and binaries to bypass signature-based antivirus scanners.',
        logSources: 'AV Scan Telemetry, AMSI (Antimalware Scan Interface) Audit Logs',
        mitigation: 'Enable deep AMSI inspection, deploy behavior-based Endpoint Detection and Response (EDR).',
        detectionRule: 'Yara: rule High_Entropy_Payload { condition: math.entropy(0, filesize) > 7.5 }'
      }
    ]
  },
  {
    name: 'Credential Access',
    techniques: [
      {
        id: 'T1110.001',
        name: 'Password Guessing',
        tactic: 'Credential Access',
        ports: [3389, 22, 445],
        description: 'Adversaries automate rapid password dictionary attacks against exposed RDP port 3389 or SSH port 22 to compromise valid user credentials.',
        logSources: 'Windows Security Event ID 4625 (Failed Logon), Linux sshd Auth Logs',
        mitigation: 'Enforce Account Lockout Thresholds (5 failed attempts), mandate Multi-Factor Authentication (MFA).',
        detectionRule: 'Sigma: EventID: 4625 | count() > 20 per minute'
      },
      {
        id: 'T1003',
        name: 'OS Credential Dump',
        tactic: 'Credential Access',
        ports: [],
        description: 'Adversaries extract plaintext credentials, NTLM hashes, and Kerberos tickets stored in Local Security Authority Subsystem Service (LSASS) memory.',
        logSources: 'Windows Process Access Event ID 10 (LSASS Handle Requested), EDR Driver Telemetry',
        mitigation: 'Enable Credential Guard (LSA Protection), restrict SeDebugPrivilege.',
        detectionRule: 'Sigma: TargetImage endswith "\\lsass.exe" and GrantedAccess includes 0x1410'
      }
    ]
  },
  {
    name: 'Command & Control',
    techniques: [
      {
        id: 'T1071.001',
        name: 'Web Protocols C2',
        tactic: 'Command & Control',
        ports: [80, 443, 4444, 8443],
        description: 'Adversaries communicate with compromised endpoints over standard HTTP/HTTPS web protocols to evade perimeter firewall inspection.',
        logSources: 'Perimeter Firewall Connection Logs, Proxy Traffic Logs, Suricata Alert Stream',
        mitigation: 'Deploy TLS Decryption and Inspection at Next-Gen Firewall (NGFW).',
        detectionRule: 'Suricata: alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Beaconing";)'
      },
      {
        id: 'T1021.001',
        name: 'Remote Desktop Protocol',
        tactic: 'Command & Control / Lateral Movement',
        ports: [3389],
        description: 'Adversaries use RDP protocol to interactively log into internal host desktops and navigate laterally across enterprise network segments.',
        logSources: 'Windows Security Event ID 4624 (Type 10 Remote Interactive Logon)',
        mitigation: 'Require Network Level Authentication (NLA), place RDP behind enterprise VPN.',
        detectionRule: 'Sigma: EventID: 4624 and LogonType: 10'
      }
    ]
  }
];

export default function MitreMatrixView({ nmapScan }) {
  const [selectedTech, setSelectedTech] = useState(TACTICS_DATA[0].techniques[0]);

  // Determine open ports from real nmapScan
  const openPortsList = (nmapScan && Array.isArray(nmapScan.openPorts))
    ? nmapScan.openPorts.map(p => p.port)
    : [];

  // Helper to check if technique matches scanned ports
  const getPortMatch = (tech) => {
    if (openPortsList.length === 0 || !tech.ports) return null;
    const match = tech.ports.find(p => openPortsList.includes(p));
    return match || null;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Grid className="w-6 h-6 text-cyan-400" />
            MITRE ATT&CK Enterprise Matrix Navigator
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Interactive enterprise threat framework. Click any technique below to inspect technical details, detection rules, and real scanner correlations.
          </p>
        </div>
      </div>

      {/* Real Scan Status Banner */}
      {nmapScan ? (
        <div className="glass-panel p-4 rounded-2xl border-l-4 border-l-emerald-500 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-emerald-300 font-bold">真實網路掃描器數據連動中：</span>
            <span className="text-slate-300">
              目標主機 <code className="text-cyan-300">{nmapScan.host}</code> 共檢測到 <strong className="text-emerald-400">{nmapScan.openPorts.length}</strong> 個開放 Port，匹配之 MITRE 技術已高亮標註。
            </span>
          </div>
        </div>
      ) : (
        <div className="glass-panel p-4 rounded-2xl border-l-4 border-l-cyan-500 flex items-center justify-between font-mono text-xs text-slate-300">
          <div>
            <span className="text-cyan-300 font-bold">標準 MITRE ATT&CK 框架視圖：</span>
            <span>系統處於基線狀態。至「Network Scanner」進行真實 Port 掃描，矩陣將自動關聯高亮；AI 劇情攻擊映射請至【模擬攻擊】。</span>
          </div>
        </div>
      )}

      {/* Interactive Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 overflow-x-auto">
        {TACTICS_DATA.map((tactic, idx) => (
          <div key={idx} className="space-y-2">
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-center font-mono text-[11px] font-bold text-slate-300">
              {tactic.name}
            </div>
            <div className="space-y-2">
              {tactic.techniques.map((tech) => {
                const matchedPort = getPortMatch(tech);
                const isSelected = selectedTech?.id === tech.id;
                return (
                  <button
                    key={tech.id}
                    onClick={() => setSelectedTech(tech)}
                    className={`w-full p-2.5 rounded-xl text-left font-mono text-xs transition-all border relative ${
                      isSelected
                        ? 'border-cyan-400 bg-cyan-500/20 text-cyan-200 shadow-md shadow-cyan-500/10'
                        : matchedPort
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-sm shadow-amber-500/20 font-bold animate-pulse'
                        : 'bg-slate-950/60 text-slate-400 border-slate-900 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[10px] text-cyan-400">{tech.id}</span>
                      {matchedPort && (
                        <span className="text-[9px] font-bold px-1 rounded bg-amber-500/30 text-amber-300 border border-amber-500/40">
                          Port {matchedPort}
                        </span>
                      )}
                    </div>
                    <div className="truncate text-slate-200 mt-1">{tech.name}</div>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Technique Details Panel */}
      {selectedTech && (
        <div className="glass-panel p-5 rounded-2xl border border-cyan-500/30 space-y-4 font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-900 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold border border-cyan-500/30">
                  {selectedTech.tactic} TACTIC
                </span>
                <span className="text-xs text-slate-400 font-bold">TECHNIQUE ID: {selectedTech.id}</span>
              </div>
              <h3 className="text-base font-bold text-white mt-1">
                {selectedTech.id} - {selectedTech.name}
              </h3>
            </div>

            {/* Scanned Match Notification */}
            {getPortMatch(selectedTech) ? (
              <div className="px-3.5 py-1.5 rounded-xl bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-bold flex items-center gap-2 shrink-0">
                <Zap className="w-4 h-4 text-amber-400 animate-bounce" />
                REAL SCAN MATCH: Target {nmapScan?.host} Port {getPortMatch(selectedTech)} Open
              </div>
            ) : (
              <span className="text-xs text-slate-400 bg-slate-900 px-3 py-1 rounded-lg border border-slate-800 shrink-0">
                Baseline Technique Inspector
              </span>
            )}
          </div>

          {/* Technique Description */}
          <div className="space-y-1">
            <div className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" /> Technical Vector Description:
            </div>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-xl border border-slate-900">
              {selectedTech.description}
            </p>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-900 space-y-1">
              <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" /> Key Log Sources & Telemetry:
              </span>
              <p className="text-slate-400">{selectedTech.logSources}</p>
            </div>

            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-900 space-y-1">
              <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" /> Recommended SOC Mitigation:
              </span>
              <p className="text-slate-400">{selectedTech.mitigation}</p>
            </div>
          </div>

          {/* Sample Detection Rule */}
          <div className="bg-slate-950 p-4 rounded-xl border border-cyan-500/20 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" /> Detection Rule & SIEM Signature:
              </span>
              <span className="text-[10px] text-slate-500">Auto-Correlated Rule</span>
            </div>
            <pre className="text-xs text-slate-300 font-mono bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              {selectedTech.detectionRule}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
