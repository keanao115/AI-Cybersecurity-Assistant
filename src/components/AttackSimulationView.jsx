import React, { useState } from 'react';
import { Zap, Play, Terminal, ShieldAlert, CheckCircle, RefreshCw, AlertTriangle, ShieldCheck, BookOpen, Bug, Activity, Grid, FileCode, Copy, Check } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';

const ATTACK_SCENARIOS = [
  {
    id: 'brute',
    title: 'RDP / SSH Password Brute-Force',
    description: 'Simulates 500+ rapid password attempts targeting DC-SRV-01 Administrator account.',
    eventLogs: [
      '[14:22:01] WIN-EVENT 4625: Logon Failure for Administrator from 185.220.101.5:54221 (Attempt 1)',
      '[14:22:02] WIN-EVENT 4625: Logon Failure for Administrator from 185.220.101.5:54222 (Attempt 2)',
      '[14:22:03] WIN-EVENT 4625: Logon Failure for Administrator from 185.220.101.5:54223 (Attempt 3)',
      '[14:22:05] ALERT TRIGGERED: Brute Force Pattern Threshold Exceeded (>100 fails/min)'
    ],
    detection: 'T1110.001 Brute Force: Password Guessing',
    aiAction: 'Trigger Firewall IP Block rule on 185.220.101.5 & Enforce Account Lockout',
    storyline: 'An external adversary initiated an automated password guessing campaign against port 3389 (RDP) on host DC-SRV-01 using account "Administrator". Over 500 failed logon attempts were registered within 60 seconds from source IP 185.220.101.5. Upon threshold breach, automated firewall filtering engaged to block origin traffic and lock target account.',
    timelineData: [
      { time: '00:00', BruteForce: 5, Scans: 10, C2Traffic: 0 },
      { time: '04:00', BruteForce: 3, Scans: 8, C2Traffic: 0 },
      { time: '08:00', BruteForce: 180, Scans: 40, C2Traffic: 0 },
      { time: '12:00', BruteForce: 520, Scans: 85, C2Traffic: 0 },
      { time: '16:00', BruteForce: 210, Scans: 30, C2Traffic: 0 },
      { time: '20:00', BruteForce: 15, Scans: 5, C2Traffic: 0 },
    ],
    severityData: [
      { name: 'Critical', value: 1, color: '#ef4444' },
      { name: 'High', value: 15, color: '#f59e0b' },
      { name: 'Medium', value: 32, color: '#06b6d4' },
      { name: 'Low', value: 10, color: '#10b981' },
    ],
    criticalCount: 1,
    highCount: 15,
    vulnerabilities: [
      {
        id: "NV-3389",
        cve: "CVE-2019-0708",
        name: "Remote Desktop Services RCE Vulnerability (BlueKeep)",
        severity: "Critical",
        cvss: 9.8,
        host: "192.168.1.10",
        port: 3389,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "An unauthenticated remote code execution vulnerability exists in Remote Desktop Services (RDP)."
      },
      {
        id: "NV-2201",
        cve: "CVE-2020-1472",
        name: "Netlogon Privilege Escalation (Zerologon)",
        severity: "Critical",
        cvss: 10.0,
        host: "DC-SRV-01",
        port: 445,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "An elevation of privilege vulnerability exists when an attacker establishes an unauthenticated Netlogon connection."
      },
      {
        id: "NV-4625",
        cve: "CWE-307",
        name: "Unenforced Account Lockout Threshold Policy",
        severity: "High",
        cvss: 7.5,
        host: "DC-SRV-01",
        port: 0,
        exploitAvailable: true,
        patchPriority: "High (P1)",
        description: "Absence of automated brute-force lockout allows rapid automated password dictionary guessing."
      }
    ],
    mitreTactics: [
      { name: 'Reconnaissance', tech: 'T1595 Active Scanning', active: true },
      { name: 'Initial Access', tech: 'T1078 Valid Accounts', active: true },
      { name: 'Execution', tech: 'T1059.003 Windows Cmd', active: false },
      { name: 'Persistence', tech: 'T1136.001 Local Account', active: false },
      { name: 'Privilege Escalation', tech: 'T1548.003 Sudo Abuse', active: false },
      { name: 'Defense Evasion', tech: 'T1070.001 Clear Event Logs', active: false },
      { name: 'Credential Access', tech: 'T1110.001 Brute Force Password Guessing', active: true },
      { name: 'Command & Control', tech: 'T1021.001 RDP Protocol', active: true },
    ],
    anomalies: [
      {
        id: "ANOM-SIM-1",
        title: "Brute Force Password Guessing Attack",
        severity: "High",
        mitreId: "T1110.001",
        target: "DC-SRV-01 (Administrator)",
        attackerIp: "185.220.101.5",
        description: "Over 500 failed login attempts detected in 60 seconds targeting Administrator RDP session.",
        remediation: "Block source IP 185.220.101.5 on perimeter firewall, enforce 5-attempt Account Lockout Policy."
      },
      {
        id: "ANOM-SIM-2",
        title: "Exposed RDP Port 3389 without NLA",
        severity: "High",
        mitreId: "T1021.001",
        target: "DC-SRV-01:3389",
        attackerIp: "185.220.101.5",
        description: "Remote Desktop Protocol service accessible directly from public internet WAN without Network Level Authentication.",
        remediation: "Place RDP service behind enterprise VPN with MFA requirement."
      }
    ],
    scripts: {
      powershell: `# CyberMind AI Generated PowerShell Containment Script for Brute Force
New-NetFirewallRule -DisplayName "CyberMind-Block-185.220.101.5" -Direction Inbound -Action Block -RemoteAddress "185.220.101.5"
Set-LocalUser -Name "Administrator" -AccountNeverExpires $false`,
      bash: `#!/bin/bash
iptables -A INPUT -s 185.220.101.5 -j DROP
echo "[+] Blocked Brute-Force Origin IP 185.220.101.5"`,
      sigma: `title: RDP Brute Force Password Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection | count() > 100`,
      yara: `rule Sim_Brute_Force_Audit {
    strings:
        $event = "WIN-EVENT 4625"
    condition:
        $event
}`,
      snort: `alert tcp 185.220.101.5 any -> $HOME_NET 3389 (msg:"Simulated RDP Brute-Force Detection"; sid:1000101;)`,
      suricata: `alert tcp 185.220.101.5 any -> $HOME_NET 3389 (msg:"Simulated RDP Brute Force Threshold Exceeded"; sid:2000101;)`
    }
  },
  {
    id: 'powershell',
    title: 'Obfuscated PowerShell C2 Beacon Download',
    description: 'Simulates cmd.exe launching powershell.exe -enc with Base64 payload shell.ps1.',
    eventLogs: [
      '[14:25:30] WIN-EVENT 4688: New Process Created: powershell.exe by cmd.exe',
      '[14:25:31] COMMAND: powershell.exe -ExecutionPolicy Bypass -enc SQBFAAGAKABOAGV3LU9i...',
      '[14:25:32] NETWORK: Outbound connection attempt to 183.220.101.5:4444 (TCP)',
      '[14:25:33] ALERT TRIGGERED: Known Cobalt Strike Stager Signature Matched'
    ],
    detection: 'T1059.001 PowerShell Command Interpreter / C2 Beaconing',
    aiAction: 'Terminate PID 4812, Quarantine shell.ps1, Block Remote IP 183.220.101.5',
    storyline: 'An adversary executed an encoded Base64 PowerShell command via cmd.exe on host DC-SRV-01. The stager attempted outbound HTTP GET request to download secondary payload shell.ps1 from remote C2 server 183.220.101.5:4444. Endpoint protection flagged the obfuscated execution string and killed the parent process tree.',
    timelineData: [
      { time: '00:00', BruteForce: 2, Scans: 10, C2Traffic: 0 },
      { time: '04:00', BruteForce: 0, Scans: 5, C2Traffic: 0 },
      { time: '08:00', BruteForce: 10, Scans: 25, C2Traffic: 45 },
      { time: '12:00', BruteForce: 5, Scans: 30, C2Traffic: 240 },
      { time: '16:00', BruteForce: 2, Scans: 15, C2Traffic: 110 },
      { time: '20:00', BruteForce: 0, Scans: 5, C2Traffic: 8 },
    ],
    severityData: [
      { name: 'Critical', value: 8, color: '#ef4444' },
      { name: 'High', value: 18, color: '#f59e0b' },
      { name: 'Medium', value: 14, color: '#06b6d4' },
      { name: 'Low', value: 5, color: '#10b981' },
    ],
    criticalCount: 8,
    highCount: 18,
    vulnerabilities: [
      {
        id: "NV-1059",
        cve: "CWE-94",
        name: "Unrestricted PowerShell Execution Policy Bypass",
        severity: "Critical",
        cvss: 9.3,
        host: "DC-SRV-01",
        port: 0,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "PowerShell script execution policy allows non-administrative bypass via -ExecutionPolicy Bypass parameter."
      },
      {
        id: "NV-4688",
        cve: "CWE-532",
        name: "Process Creation Command Line Auditing Disabled",
        severity: "High",
        cvss: 7.4,
        host: "DC-SRV-01",
        port: 0,
        exploitAvailable: true,
        patchPriority: "High (P1)",
        description: "Windows Security Log Event 4688 process command-line logging is not strictly enforced."
      },
      {
        id: "NV-1832",
        cve: "CWE-284",
        name: "Unfiltered Outbound C2 Beacon Connection (Port 4444)",
        severity: "Critical",
        cvss: 9.1,
        host: "183.220.101.5",
        port: 4444,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "Host firewall rules permit outbound TCP traffic to unverified external IP on non-standard C2 port."
      }
    ],
    mitreTactics: [
      { name: 'Reconnaissance', tech: 'T1595 Active Scanning', active: false },
      { name: 'Initial Access', tech: 'T1190 Exploit Public App', active: false },
      { name: 'Execution', tech: 'T1059.001 PowerShell Stager', active: true },
      { name: 'Persistence', tech: 'T1136.001 Local Account', active: true },
      { name: 'Privilege Escalation', tech: 'T1548.003 Sudo Abuse', active: false },
      { name: 'Defense Evasion', tech: 'T1027 Obfuscated Files', active: true },
      { name: 'Credential Access', tech: 'T1003 OS Credential Dump', active: false },
      { name: 'Command & Control', tech: 'T1071.001 C2 Web Protocol', active: true },
    ],
    anomalies: [
      {
        id: "ANOM-SIM-1",
        title: "Obfuscated PowerShell Execution (C2 Stager)",
        severity: "Critical",
        mitreId: "T1059.001",
        target: "DC-SRV-01 (powershell.exe)",
        attackerIp: "183.220.101.5",
        description: "Suspicious Base64 encoded PowerShell script initiated web download of external payload shell.ps1.",
        remediation: "Immediately kill PID 4812, block remote C2 IP 183.220.101.5, run EDR memory scan."
      },
      {
        id: "ANOM-SIM-2",
        title: "Outbound Cobalt Strike C2 Traffic Drop",
        severity: "Critical",
        mitreId: "T1071.001",
        target: "DC-SRV-01 -> 183.220.101.5:4444",
        attackerIp: "183.220.101.5",
        description: "Internal host attempting beaconing to known adversary command & control server on port 4444.",
        remediation: "Isolate host DC-SRV-01 from corporate VLAN, perform full forensic triage."
      }
    ],
    scripts: {
      powershell: `# CyberMind AI Generated PowerShell Containment Script for C2 Stager
Get-Process powershell | Where-Object { $_.CommandLine -like "*-enc*" } | Stop-Process -Force
New-NetFirewallRule -DisplayName "CyberMind-Block-C2-183.220.101.5" -Direction Outbound -Action Block -RemoteAddress "183.220.101.5"`,
      bash: `#!/bin/bash
pkill -f "shell.ps1"
iptables -A OUTPUT -d 183.220.101.5 -j DROP`,
      sigma: `title: Obfuscated PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - 'DownloadString'
    condition: selection`,
      yara: `rule Sim_PowerShell_C2_Stager {
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "-ExecutionPolicy Bypass" nocase
    condition:
        all of them
}`,
      snort: `alert tcp $HOME_NET any -> 183.220.101.5 4444 (msg:"Simulated PowerShell C2 Beacon Download"; sid:1000102;)`,
      suricata: `alert http $HOME_NET any -> 183.220.101.5 any (msg:"Simulated Malicious Payload shell.ps1 Download"; sid:2000102;)`
    }
  },
  {
    id: 'ransomware',
    title: 'LockBit Ransomware Shadow Copy Destruction',
    description: 'Simulates vssadmin.exe delete shadows /all /quiet execution.',
    eventLogs: [
      '[14:28:00] WIN-EVENT 4688: Process Created vssadmin.exe delete shadows /all /quiet',
      '[14:28:01] FILE-SYSTEM: Bulk file rename detected under C:\\Users\\Administrator\\Documents (.lockbit)',
      '[14:28:02] CRITICAL ALERT: Ransomware Shadow Copy Invalidation Activity Detected'
    ],
    detection: 'T1490 Inhibit System Recovery / Ransomware Execution',
    aiAction: 'Instantly Isolate Host VLAN 102, Suspend Process Tree, Restore Volume Shadow Copies',
    storyline: 'A simulated ransomware executable executed vssadmin.exe to purge local Volume Shadow Copies, preventing system recovery. Rapid file modification patterns were detected across user document directories with extension append .lockbit. Automated response isolated host network adapter VLAN 102.',
    timelineData: [
      { time: '00:00', BruteForce: 0, Scans: 5, C2Traffic: 0 },
      { time: '04:00', BruteForce: 0, Scans: 2, C2Traffic: 0 },
      { time: '08:00', BruteForce: 20, Scans: 50, C2Traffic: 15 },
      { time: '12:00', BruteForce: 85, Scans: 190, C2Traffic: 180 },
      { time: '16:00', BruteForce: 300, Scans: 400, C2Traffic: 350 },
      { time: '20:00', BruteForce: 10, Scans: 20, C2Traffic: 5 },
    ],
    severityData: [
      { name: 'Critical', value: 16, color: '#ef4444' },
      { name: 'High', value: 24, color: '#f59e0b' },
      { name: 'Medium', value: 8, color: '#06b6d4' },
      { name: 'Low', value: 2, color: '#10b981' },
    ],
    criticalCount: 16,
    highCount: 24,
    vulnerabilities: [
      {
        id: "NV-8472",
        cve: "CVE-2017-0144",
        name: "MS17-010 SMB Server RCE (EternalBlue)",
        severity: "Critical",
        cvss: 9.8,
        host: "192.168.1.10",
        port: 445,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) server used for lateral movement."
      },
      {
        id: "NV-1490",
        cve: "CWE-269",
        name: "Unrestricted Volume Shadow Copy Service Invalidation",
        severity: "Critical",
        cvss: 9.5,
        host: "DC-SRV-01",
        port: 0,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "vssadmin.exe allowed administrative process to silently purge backup volume snapshots."
      },
      {
        id: "NV-5012",
        cve: "CVE-2023-38831",
        name: "WinRAR Spoofing File Extension Code Execution",
        severity: "High",
        cvss: 7.8,
        host: "192.168.1.102",
        port: 0,
        exploitAvailable: true,
        patchPriority: "High (P1)",
        description: "Processing of crafted zip archives allows execution of arbitrary code when opening benign-looking files."
      }
    ],
    mitreTactics: [
      { name: 'Reconnaissance', tech: 'T1595 Active Scanning', active: false },
      { name: 'Initial Access', tech: 'T1210 Exploitation Remote Services', active: true },
      { name: 'Execution', tech: 'T1204 User Execution', active: true },
      { name: 'Persistence', tech: 'T1136 Local Account', active: false },
      { name: 'Privilege Escalation', tech: 'T1068 Exploit Vulnerability', active: true },
      { name: 'Defense Evasion', tech: 'T1070 Clear Logs', active: true },
      { name: 'Impact', tech: 'T1490 Inhibit System Recovery', active: true },
      { name: 'Impact', tech: 'T1486 Data Encrypted Impact', active: true },
    ],
    anomalies: [
      {
        id: "ANOM-SIM-1",
        title: "Ransomware Volume Shadow Copy Invalidation",
        severity: "Critical",
        mitreId: "T1490",
        target: "DC-SRV-01 (vssadmin.exe)",
        attackerIp: "Local Executable Payload",
        description: "Execution of vssadmin.exe delete shadows /all /quiet to inhibit system recovery prior to encryption.",
        remediation: "Instantly isolate host VLAN 102, suspend process tree, initiate Volume Shadow Copy snapshot restore."
      },
      {
        id: "ANOM-SIM-2",
        title: "Bulk File Modification & .lockbit Extension Append",
        severity: "Critical",
        mitreId: "T1486",
        target: "C:\\Users\\Administrator\\Documents",
        attackerIp: "Local Executable Payload",
        description: "Bulk file rename and encryption detected under document folders.",
        remediation: "Halt disk I/O, isolate host, deploy immutable backup rollback playbook."
      }
    ],
    scripts: {
      powershell: `# CyberMind AI Generated Ransomware Emergency Containment Script
Stop-Process -Name "vssadmin" -Force
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Write-Host "[!] Ransomware Process Terminated & Host Network Isolated." -ForegroundColor Red`,
      bash: `#!/bin/bash
pkill -f "vssadmin"
pkill -f ".lockbit"
echo "[+] Isolated Host Network Interfaces"`,
      sigma: `title: Volume Shadow Copy Deletion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith: '\\vssadmin.exe'
        CommandLine|contains: 'delete shadows'
    condition: selection`,
      yara: `rule Sim_LockBit_Ransomware_Payload {
    strings:
        $vss = "vssadmin.exe delete shadows"
        $ext = ".lockbit"
    condition:
        any of them
}`,
      snort: `alert tcp any any -> any 445 (msg:"Simulated Ransomware SMB Lateral Movement"; sid:1000103;)`,
      suricata: `alert smb any any -> any 445 (msg:"Simulated LockBit Ransomware Activity"; sid:2000103;)`
    }
  },
  {
    id: 'sqli',
    title: 'Web Application SQL Injection (SQLi)',
    description: 'Simulates GET /products.php?id=1%27%20UNION%20SELECT%201,username,password%20FROM%20users--',
    eventLogs: [
      '[14:30:10] NGINX-LOG: 192.168.1.155 - - "GET /products.php?id=1%27%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 4512',
      '[14:30:11] WAF ALERT: SQL Injection Signature ID 942100 Matched in URI parameter id'
    ],
    detection: 'OWASP A03:2021 Injection / T1190 Exploit Public-Facing Application',
    aiAction: 'Block Source IP 192.168.1.155 at Nginx WAF Layer, Sanitize Input Parameters',
    storyline: 'An attacker probed public endpoint /products.php using SQL UNION injection syntax to extract credential tables from back-end database. Web Application Firewall (WAF) rule 942100 matched the malformed request and blocked client IP address 192.168.1.155.',
    timelineData: [
      { time: '00:00', BruteForce: 0, Scans: 30, C2Traffic: 0 },
      { time: '04:00', BruteForce: 0, Scans: 15, C2Traffic: 0 },
      { time: '08:00', BruteForce: 0, Scans: 280, C2Traffic: 0 },
      { time: '12:00', BruteForce: 0, Scans: 450, C2Traffic: 0 },
      { time: '16:00', BruteForce: 0, Scans: 190, C2Traffic: 0 },
      { time: '20:00', BruteForce: 0, Scans: 40, C2Traffic: 0 },
    ],
    severityData: [
      { name: 'Critical', value: 3, color: '#ef4444' },
      { name: 'High', value: 19, color: '#f59e0b' },
      { name: 'Medium', value: 22, color: '#06b6d4' },
      { name: 'Low', value: 12, color: '#10b981' },
    ],
    criticalCount: 3,
    highCount: 19,
    vulnerabilities: [
      {
        id: "NV-9421",
        cve: "CVE-2023-SQLI",
        name: "OWASP A03:2021 SQL Injection in /products.php",
        severity: "Critical",
        cvss: 9.8,
        host: "web-prod-01",
        port: 80,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "Unsanitized user input in query parameter id permits unauthenticated SQL database exfiltration."
      },
      {
        id: "NV-10492",
        cve: "CVE-2021-44228",
        name: "Apache Log4j Remote Code Execution (Log4Shell)",
        severity: "Critical",
        cvss: 10.0,
        host: "192.168.1.50",
        port: 8080,
        exploitAvailable: true,
        patchPriority: "Immediate (P0)",
        description: "JNDI lookup feature in Apache Log4j 2.0-beta9 through 2.15.0 allows unauthenticated RCE via payload string."
      },
      {
        id: "NV-8001",
        cve: "CWE-209",
        name: "Verbose Database Error Information Disclosure",
        severity: "High",
        cvss: 7.2,
        host: "web-prod-01",
        port: 80,
        exploitAvailable: true,
        patchPriority: "High (P1)",
        description: "Application returns full SQL stack trace error messages to client browser on malformed request."
      }
    ],
    mitreTactics: [
      { name: 'Reconnaissance', tech: 'T1595 Active Web Scan', active: true },
      { name: 'Initial Access', tech: 'T1190 Exploit Public App (SQLi)', active: true },
      { name: 'Execution', tech: 'T1059 Command Interpreter', active: false },
      { name: 'Persistence', tech: 'T1053 Scheduled Task', active: false },
      { name: 'Privilege Escalation', tech: 'T1068 Exploit Vulnerability', active: false },
      { name: 'Defense Evasion', tech: 'T1562 Impair WAF Defenses', active: true },
      { name: 'Credential Access', tech: 'T1552 Credentials in DB', active: true },
      { name: 'Command & Control', tech: 'T1071.001 Web Protocols', active: false },
    ],
    anomalies: [
      {
        id: "ANOM-SIM-1",
        title: "Web Application SQL Injection (UNION SELECT)",
        severity: "Critical",
        mitreId: "T1190",
        target: "web-prod-01 (/products.php)",
        attackerIp: "192.168.1.155",
        description: "Attacker sent HTTP GET request containing SQL UNION SELECT syntax in parameter id.",
        remediation: "Block IP 192.168.1.155 on Nginx WAF layer, replace raw SQL queries with PDO parameterized queries."
      },
      {
        id: "ANOM-SIM-2",
        title: "Database Credentials Exfiltration Attempt",
        severity: "High",
        mitreId: "T1552",
        target: "MySQL (users table)",
        attackerIp: "192.168.1.155",
        description: "SQL payload probed columns username,password from database schema.",
        remediation: "Sanitize HTTP URI inputs, disable verbose database stack trace error output."
      }
    ],
    scripts: {
      powershell: `# CyberMind AI Generated PowerShell Containment Script for SQLi
New-NetFirewallRule -DisplayName "CyberMind-Block-SQLi-192.168.1.155" -Direction Inbound -Action Block -RemoteAddress "192.168.1.155"`,
      bash: `#!/bin/bash
iptables -A INPUT -s 192.168.1.155 -j DROP
nginx -s reload # Enable Nginx WAF Rule 942100`,
      sigma: `title: Web Application SQL Injection
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains: 'UNION SELECT'
    condition: selection`,
      yara: `rule Sim_SQL_Injection_Attack {
    strings:
        $sql1 = "UNION SELECT" nocase
        $sql2 = "FROM users" nocase
    condition:
        all of them
}`,
      snort: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"Simulated SQL Injection UNION SELECT"; content:"UNION SELECT"; nocase; sid:1000104;)`,
      suricata: `alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Simulated SQLi URI Parameter Injection"; content:"products.php?id="; http_uri; sid:2000104;)`
    }
  }
];

export default function AttackSimulationView() {
  const [runningId, setRunningId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [activeScenario, setActiveScenario] = useState(ATTACK_SCENARIOS[0]);
  const [copied, setCopied] = useState(false);
  const [activeScriptTab, setActiveScriptTab] = useState('powershell');

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSimulate = (scenario) => {
    setRunningId(scenario.id);
    setActiveScenario(scenario);
    setLogs([]);

    scenario.eventLogs.forEach((logLine, index) => {
      setTimeout(() => {
        setLogs(prev => [...prev, logLine]);
        if (index === scenario.eventLogs.length - 1) {
          setRunningId(null);
        }
      }, (index + 1) * 600);
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Zap className="w-6 h-6 text-amber-400" />
            AI 模擬攻擊、劇情威脅與漏洞演練中心 (Attack Simulation Center)
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            切換不同模擬攻擊劇情時，時間軸、威脅等級、漏洞報告與 MITRE ATT&CK 戰術會即時連動動態變化。
          </p>
        </div>
      </div>

      {/* Scenarios Selection */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {ATTACK_SCENARIOS.map((scen) => (
          <div
            key={scen.id}
            onClick={() => setActiveScenario(scen)}
            className={`glass-panel p-5 rounded-2xl border flex flex-col justify-between space-y-4 cursor-pointer transition-all ${
              activeScenario?.id === scen.id
                ? 'border-amber-500/60 bg-amber-500/10 shadow-lg shadow-amber-500/10 scale-[1.02]'
                : 'border-slate-800 hover:border-amber-500/30'
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {scen.id.toUpperCase()} SCENARIO
                </span>
                <span className="text-xs font-mono text-cyan-400">{scen.detection.split(' ')[0]}</span>
              </div>
              <h4 className="text-sm font-bold text-white">{scen.title}</h4>
              <p className="text-xs text-slate-400 mt-1">{scen.description}</p>
            </div>

            <button
              onClick={(e) => { e.stopPropagation(); handleSimulate(scen); }}
              disabled={runningId !== null}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-amber-500 to-red-600 hover:from-amber-400 hover:to-red-500 text-white font-mono text-xs font-bold shadow-lg shadow-amber-500/20 transition-all disabled:opacity-50"
            >
              {runningId === scen.id ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white" />}
              {runningId === scen.id ? 'Simulating Attack...' : 'Launch Simulation'}
            </button>
          </div>
        ))}
      </div>

      {/* AI Attack Storyline Narrative Display Box */}
      {activeScenario && (
        <div className="glass-panel p-5 rounded-2xl border-l-4 border-l-amber-400 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-amber-400" />
              AI 模擬攻擊劇情敘事 (AI Attack Storyline Narrative) - [{activeScenario.title}]
            </h3>
            <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
              ACTIVE SCENARIO
            </span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed font-mono">
            {activeScenario.storyline}
          </p>
        </div>
      )}

      {/* Interactive Simulation Console */}
      <div className="glass-panel p-5 rounded-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-900 pb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-mono">SOC Real-Time Event Stream Console ({activeScenario.title})</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {runningId ? <span className="text-amber-400 font-bold flex items-center gap-1"><RefreshCw className="w-3 h-3 animate-spin" /> EXECUTING PAYLOAD</span> : 'IDLE / READY'}
          </span>
        </div>

        <div className="bg-slate-950 border border-slate-900 rounded-xl p-4 font-mono text-xs max-h-64 overflow-y-auto space-y-2">
          {logs.length === 0 ? (
            <div className="text-slate-600 italic">Click "Launch Simulation" on [{activeScenario.title}] to stream live telemetry...</div>
          ) : (
            logs.map((line, idx) => (
              <div key={idx} className={`py-1 px-2 rounded flex items-center gap-2 ${
                line.includes('ALERT') || line.includes('CRITICAL') ? 'bg-red-500/20 text-red-300 border-l-2 border-red-500 font-bold' : 'text-slate-300'
              }`}>
                <span>{line}</span>
              </div>
            ))
          )}
        </div>

        {/* AI Counter-Measure Trigger Display */}
        {activeScenario && logs.length > 0 && (
          <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400"><ShieldCheck className="w-5 h-5" /></div>
              <div>
                <div className="text-cyan-300 font-bold">CyberMind AI Automated Counter-Measure Triggered</div>
                <div className="text-slate-400">{activeScenario.aiAction}</div>
              </div>
            </div>
            <span className="px-3 py-1 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-lg text-[10px] font-bold">
              MITIGATED
            </span>
          </div>
        )}
      </div>

      {/* Dynamic Simulated Charts Section: Attack Timeline & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scenario-Specific Attack Timeline */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl flex flex-col justify-between border border-amber-500/20">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-bold text-sm text-amber-300 flex items-center gap-2">
                <Activity className="w-4 h-4 text-amber-400" />
                【{activeScenario.title}】劇情報告 - 攻擊時間軸 (24 Hours Timeline)
              </h3>
              <p className="text-xs text-slate-400 font-mono">Dynamic threat vector volume generated by active scenario</p>
            </div>
            <span className="text-xs font-mono text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded-md border border-amber-500/20">
              {activeScenario.id.toUpperCase()} FEED
            </span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activeScenario.timelineData}>
                <defs>
                  <linearGradient id="simColorBrute" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="simColorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="simColorC2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: '#f59e0b', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="BruteForce" stroke="#ef4444" fillOpacity={1} fill="url(#simColorBrute)" name="Simulated Brute Force" />
                <Area type="monotone" dataKey="Scans" stroke="#06b6d4" fillOpacity={1} fill="url(#simColorScans)" name="Simulated Scans / Web SQLi" />
                <Area type="monotone" dataKey="C2Traffic" stroke="#8b5cf6" fillOpacity={1} fill="url(#simColorC2)" name="Simulated C2 Traffic" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Scenario-Specific Severity Breakdown */}
        <div className="glass-panel p-5 rounded-2xl flex flex-col justify-between border border-amber-500/20">
          <div>
            <h3 className="font-bold text-sm text-amber-300 mb-1 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              【{activeScenario.title}】劇情報告 - 威脅等級 (Threat Severity)
            </h3>
            <p className="text-xs text-slate-400 font-mono">Severity metrics for active scenario</p>
          </div>
          <div className="h-52 w-full flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={activeScenario.severityData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={5} dataKey="value">
                  {activeScenario.severityData.map((entry, index) => (
                    <Cell key={`sim-cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderRadius: '8px' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 text-center text-xs font-mono pt-2 border-t border-slate-800">
            <div className="bg-red-500/10 p-2 rounded-lg border border-red-500/20 text-red-300">
              <span className="block font-bold text-sm">{activeScenario.criticalCount}</span> Critical
            </div>
            <div className="bg-amber-500/10 p-2 rounded-lg border border-amber-500/20 text-amber-300">
              <span className="block font-bold text-sm">{activeScenario.highCount}</span> High
            </div>
          </div>
        </div>
      </div>

      {/* Scenario-Specific Vulnerabilities Section */}
      <div className="glass-panel p-5 rounded-2xl border border-amber-500/20 space-y-4">
        <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
          <Bug className="w-4 h-4 text-amber-400" />
          【{activeScenario.title}】劇情報告 - 漏洞掃描檢測報告 (Storyline Vulnerabilities)
        </h3>
        <div className="space-y-3">
          {activeScenario.vulnerabilities.map((item) => (
            <div key={item.id} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded font-bold ${
                    item.severity === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    CVSS {item.cvss} ({item.severity})
                  </span>
                  <span className="font-bold text-cyan-300">{item.cve}</span>
                  <span className="text-slate-200">{item.name}</span>
                </div>
                <div className="text-slate-400">{item.description}</div>
              </div>
              <span className="px-3 py-1 bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg shrink-0 text-[10px] font-bold">
                {activeScenario.id.toUpperCase()} VULN
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Scenario-Specific Threat Analysis & Containment Scripts Generator */}
      <div className="glass-panel p-5 rounded-2xl border border-amber-500/20 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-900 pb-3">
          <div>
            <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              【{activeScenario.title}】劇情報告 - 威脅分析與處置腳本生成 (Simulated Threat Analysis & Containment)
            </h3>
            <p className="text-xs text-slate-400 font-mono">Dynamic threat breakdown and one-click containment scripts generated for active scenario</p>
          </div>

          {/* Script Language Tabs */}
          <div className="flex flex-wrap items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800 text-xs font-mono">
            {['powershell', 'bash', 'sigma', 'yara', 'snort', 'suricata'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveScriptTab(tab)}
                className={`px-3 py-1.5 rounded-lg transition-all capitalize ${
                  activeScriptTab === tab
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* Dynamic Threat Anomalies Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {(activeScenario?.anomalies || []).map((anom) => (
            <div key={anom.id} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-start justify-between">
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                    anom.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                    'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  }`}>
                    {anom.severity} Severity
                  </span>
                  <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                    {anom.mitreId}
                  </span>
                </div>
                <h4 className="text-sm font-bold text-white mt-2">{anom.title}</h4>
                <p className="text-xs text-slate-400 mt-1">{anom.description}</p>
              </div>

              <div className="space-y-1.5 text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                <div className="flex justify-between">
                  <span className="text-slate-500">Target System:</span>
                  <span className="text-slate-300 font-semibold">{anom.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Attacker Origin:</span>
                  <span className="text-red-400 font-semibold">{anom.attackerIp}</span>
                </div>
              </div>

              <div className="text-xs text-slate-300 bg-slate-900/40 p-2.5 rounded-lg border border-slate-800">
                <span className="font-bold text-emerald-400 flex items-center gap-1 mb-1">
                  <ShieldCheck className="w-3.5 h-3.5" /> AI Recommended Fix:
                </span>
                {anom.remediation}
              </div>
            </div>
          ))}
        </div>

        {/* Script Preview Box */}
        <div className="relative rounded-xl bg-slate-950 border border-amber-500/20 p-4 font-mono text-xs overflow-x-auto">
          <button
            onClick={() => handleCopy(activeScenario?.scripts?.[activeScriptTab] || '')}
            className="absolute top-3 right-3 flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 transition-all text-xs font-semibold"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? "Copied!" : "Copy Script"}
          </button>
          <pre className="text-slate-300 leading-relaxed">
            {activeScenario?.scripts?.[activeScriptTab] || '# Script loading...'}
          </pre>
        </div>
      </div>

      {/* Scenario-Specific MITRE ATT&CK Tactics Highlights */}
      <div className="glass-panel p-5 rounded-2xl border border-amber-500/20 space-y-4">
        <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
          <Grid className="w-4 h-4 text-amber-400" />
          【{activeScenario.title}】劇情報告 - MITRE ATT&CK 戰術連動映射 (Storyline MITRE Tactics)
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 font-mono text-xs">
          {activeScenario.mitreTactics.map((item, idx) => (
            <div key={idx} className={`p-3 rounded-xl text-center space-y-1 border ${
              item.active
                ? 'bg-red-500/20 border-red-500/40 text-red-300 font-bold shadow-sm shadow-red-500/20 animate-pulse'
                : 'bg-slate-950/60 border-slate-900 text-slate-500'
            }`}>
              <div className="text-[10px] text-slate-400 uppercase">{item.name}</div>
              <div className="text-[11px] font-mono">{item.tech}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
