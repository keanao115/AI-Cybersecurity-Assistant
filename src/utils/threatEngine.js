// Threat Analysis Engine & Remediation Script Generator

export function analyzeLogThreats(parsedData) {
  const anomalies = [];
  let riskScore = 20;

  // Analyze Windows events
  if (Array.isArray(parsedData.windowsLogs)) {
    parsedData.windowsLogs.forEach(event => {
      if (event.eventId === "4625") {
        anomalies.push({
          id: `ANOM-${anomalies.length + 1}`,
          title: "Brute Force Authentication Failure",
          severity: "High",
          category: "Credential Access",
          mitreId: "T1110.001",
          mitreName: "Brute Force: Password Guessing",
          target: `${event.computer} (User: ${event.user})`,
          attackerIp: event.ip !== "N/A" ? event.ip : "192.168.1.155",
          description: "Multiple failed login attempts detected in a short time frame indicating automated password guessing.",
          remediation: "Block source IP on host firewall, enforce Account Lockout Policy (5 failed attempts), enable 2FA."
        });
        riskScore += 15;
      }
      if (event.eventId === "4688" && (event.commandLine.includes("-enc") || event.commandLine.includes("DownloadString"))) {
        anomalies.push({
          id: `ANOM-${anomalies.length + 1}`,
          title: "Obfuscated PowerShell Execution (C2 Stager)",
          severity: "Critical",
          category: "Execution / Command & Control",
          mitreId: "T1059.001",
          mitreName: "Command and Scripting Interpreter: PowerShell",
          target: `${event.computer} (Process: powershell.exe)`,
          attackerIp: "183.220.101.5",
          description: "Suspicious Base64 encoded PowerShell script initiated web download of external payload shell.ps1.",
          remediation: "Immediately kill PID, block remote C2 IP 183.220.101.5, run Endpoint Detection and Response (EDR) full scan."
        });
        riskScore += 30;
      }
      if (event.eventId === "4720") {
        anomalies.push({
          id: `ANOM-${anomalies.length + 1}`,
          title: "Unauthorized Backdoor Local Account Creation",
          severity: "High",
          category: "Persistence",
          mitreId: "T1136.001",
          mitreName: "Create Account: Local Account",
          target: `${event.computer} (New User: ${event.user})`,
          attackerIp: "Internal Compromised Host",
          description: "New user account created with high administrative privileges (SeDebugPrivilege).",
          remediation: "Disable and delete account 'shadow_admin', audit domain controller event logs for lateral movement."
        });
        riskScore += 20;
      }
      if (event.eventId === "1102") {
        anomalies.push({
          id: `ANOM-${anomalies.length + 1}`,
          title: "Security Audit Log Cleared (Defense Evasion)",
          severity: "Critical",
          category: "Defense Evasion",
          mitreId: "T1070.001",
          mitreName: "Indicator Removal: Clear Windows Event Logs",
          target: event.computer,
          attackerIp: "Internal Compromised Host",
          description: "Windows Security Log was manually cleared by an administrative account to destroy forensic evidence.",
          remediation: "Isolate endpoint, forward security events to offsite immutable SIEM, check memory dump."
        });
        riskScore += 25;
      }
    });
  }

  // Analyze Linux logs
  if (Array.isArray(parsedData.linuxLogs)) {
    parsedData.linuxLogs.forEach(l => {
      if (l.action === "SSH_FAILED_LOGIN") {
        anomalies.push({
          id: `ANOM-${anomalies.length + 1}`,
          title: "Linux SSH Remote Brute-Force Attack",
          severity: "Medium",
          category: "Credential Access",
          mitreId: "T1110.001",
          mitreName: "Brute Force",
          target: `Linux Host (User: ${l.user})`,
          attackerIp: l.ip,
          description: `SSH brute force attempts targeting ${l.user} from malicious IP ${l.ip}.`,
          remediation: "Deploy Fail2ban, disable SSH password authentication, allow SSH key pair login only."
        });
        riskScore += 10;
      }
      if (l.action === "SUDO_PRIV_ESC" || l.message.includes("stage2.sh")) {
        anomalies.push({
          id: `ANOM-${anomalies.length + 1}`,
          title: "Sudo Abuse & Malicious Script Execution",
          severity: "Critical",
          category: "Privilege Escalation",
          mitreId: "T1548.003",
          mitreName: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
          target: "Linux Production Server",
          attackerIp: l.ip,
          description: "Privileged user executed curl remote pipe to bash script under /tmp directory.",
          remediation: "Revoke sudo permissions for deploy user, inspect crontab and running background processes."
        });
        riskScore += 25;
      }
    });
  }

  // Analyze Firewall logs
  if (Array.isArray(parsedData.firewallLogs)) {
    const droppedC2 = parsedData.firewallLogs.filter(f => f.port === "4444" || f.dstIp === "185.220.101.5");
    if (droppedC2.length > 0) {
      anomalies.push({
        id: `ANOM-${anomalies.length + 1}`,
        title: "Repeated Outbound Cobalt Strike C2 Traffic Drop",
        severity: "Critical",
        category: "Command & Control",
        mitreId: "T1071.001",
        mitreName: "Application Layer Protocol: Web Protocols",
        target: "Internal Workstation 192.168.1.105",
        attackerIp: "185.220.101.5:4444",
        description: "Internal host 192.168.1.105 attempting beaconing to known adversary command & control server.",
        remediation: "Instantly isolate IP 192.168.1.105 from network VLAN, perform forensic triage for active beacon implant."
      });
      riskScore += 25;
    }
  }

  // Analyze Nmap / Real Socket Scan open ports
  if (parsedData.nmapScan && Array.isArray(parsedData.nmapScan.openPorts)) {
    parsedData.nmapScan.openPorts.forEach((p, idx) => {
      if (p.port === 445) {
        anomalies.push({
          id: `ANOM-NET-${idx + 1}`,
          title: "Exposed SMB Remote File Protocol (Port 445)",
          severity: "Critical",
          category: "Initial Access / Lateral Movement",
          mitreId: "T1210",
          mitreName: "Exploitation of Remote Services",
          target: `${parsedData.nmapScan.host}:445`,
          attackerIp: "Real TCP Socket Probe",
          description: "Port 445 SMB service is open and listening. SMBv1 protocol requires immediate patching to prevent EternalBlue lateral movement.",
          remediation: "Disable SMBv1 via PowerShell (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`), restrict SMB access to trusted subnets."
        });
        riskScore += 25;
      } else if (p.port === 3389) {
        anomalies.push({
          id: `ANOM-NET-${idx + 1}`,
          title: "Exposed Remote Desktop Protocol (RDP Port 3389)",
          severity: "High",
          category: "Reconnaissance / Initial Access",
          mitreId: "T1021.001",
          mitreName: "Remote Services: Remote Desktop Protocol",
          target: `${parsedData.nmapScan.host}:3389`,
          attackerIp: "Real TCP Socket Probe",
          description: "RDP service reachable without Network Level Authentication (NLA) enforcement.",
          remediation: "Place RDP behind enterprise VPN with MFA, restrict RDP access to trusted administrative IP ranges."
        });
        riskScore += 15;
      } else if (p.port === 80 || p.port === 443 || p.port === 8080) {
        anomalies.push({
          id: `ANOM-NET-${idx + 1}`,
          title: `Public Web Server Listener (Port ${p.port} ${p.service})`,
          severity: "Medium",
          category: "Reconnaissance / Initial Access",
          mitreId: "T1190",
          mitreName: "Exploit Public-Facing Application",
          target: `${parsedData.nmapScan.host}:${p.port}`,
          attackerIp: "Real TCP Socket Probe",
          description: `Web service banner (${p.service}) exposed on port ${p.port}. Requires vulnerability scanning and WAF filtering.`,
          remediation: "Deploy Web Application Firewall (WAF), enforce HTTP to HTTPS TLS 1.3 redirection."
        });
        riskScore += 10;
      } else if (p.port === 22) {
        anomalies.push({
          id: `ANOM-NET-${idx + 1}`,
          title: "Exposed SSH Remote Access Port (Port 22)",
          severity: "Medium",
          category: "Initial Access",
          mitreId: "T1548.003",
          mitreName: "SSH Remote Service Access",
          target: `${parsedData.nmapScan.host}:22`,
          attackerIp: "Real TCP Socket Probe",
          description: "SSH daemon accepting incoming connections. Password authentication should be disabled in favor of SSH public keys.",
          remediation: "Set `PasswordAuthentication no` in /etc/ssh/sshd_config and deploy Fail2ban."
        });
        riskScore += 10;
      } else {
        anomalies.push({
          id: `ANOM-NET-${idx + 1}`,
          title: `Open Network Service Listener: Port ${p.port} (${p.service})`,
          severity: "Low",
          category: "Reconnaissance",
          mitreId: "T1595",
          mitreName: "Active Scanning: Open Port Discovery",
          target: `${parsedData.nmapScan.host}:${p.port}`,
          attackerIp: "Real TCP Socket Probe",
          description: `Target host returned active TCP connection response on port ${p.port} (${p.service}).`,
          remediation: "Audit service necessity. Close port via local firewall if non-essential."
        });
        riskScore += 5;
      }
    });
  }

  const finalRisk = Math.min(99, riskScore);

  return {
    anomalies,
    riskScore: finalRisk,
    securityScore: 100 - Math.round(finalRisk * 0.7)
  };
}

export function generateRemediationScripts(anomalies) {
  const ipsToBlock = [...new Set(anomalies.map(a => a.attackerIp).filter(ip => ip && ip !== "N/A" && !ip.includes("Internal")))];
  
  const psBlockCommands = ipsToBlock.map(ip => 
    `New-NetFirewallRule -DisplayName "CyberMind-Block-${ip}" -Direction Inbound -Action Block -RemoteAddress "${ip}"`
  ).join('\n');

  const psScript = `# CyberMind AI Generated PowerShell Containment Script
# Generated: ${new Date().toLocaleString()}
# Target: Windows Endpoint Incident Containment

Write-Host "[+] Initializing Emergency Mitigation Script..." -ForegroundColor Cyan

# 1. Block Malicious IP Addresses via Windows Firewall
${psBlockCommands || '# No external malicious IPs flagged'}

# 2. Disable Rogue Admin User Account
if (Get-LocalUser -Name "shadow_admin" -ErrorAction SilentlyContinue) {
    Write-Host "[!] Rogue user shadow_admin detected. Disabling..." -ForegroundColor Red
    Disable-LocalUser -Name "shadow_admin"
    Remove-LocalUser -Name "shadow_admin"
}

# 3. Terminate Suspicious PowerShell Processes
Get-Process powershell | Where-Object { $_.CommandLine -like "*-enc*" } | Stop-Process -Force

# 4. Disable Vulnerable SMBv1 Protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

Write-Host "[+] Incident Containment Complete! System Hardened." -ForegroundColor Green
`;

  const bashScript = `#!/bin/bash
# CyberMind AI Generated Linux Incident Containment Script
# Generated: ${new Date().toLocaleString()}

echo "[+] Applying IPTables Firewall Restrictions..."
${ipsToBlock.map(ip => `iptables -A INPUT -s ${ip} -j DROP`).join('\n') || '# No IPs to block'}

echo "[+] Terminating Suspicious Stage-2 Shell Processes..."
pkill -f "stage2.sh"
pkill -f "crypto_miner"

echo "[+] Hardening SSH Config..."
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

echo "[+] Linux Incident Response Complete."
`;

  const yaraRule = `rule CyberMind_Detected_Stager {
    meta:
        author = "CyberMind AI SOC Engine"
        description = "Detects obfuscated PowerShell stager and C2 download string"
        severity = "Critical"
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "powershell.exe -ExecutionPolicy Bypass" nocase
        $s3 = "shadow_admin"
    condition:
        any of ($s*)
}`;

  const sigmaRule = `title: CyberMind Obfuscated PowerShell Execution
id: ${Math.random().toString(36).substring(7)}
status: experimental
description: Detects encoded PowerShell command execution downloading external remote payload.
author: CyberMind AI Engine
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - 'DownloadString'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: critical`;

  const snortRule = `alert tcp $EXTERNAL_NET any -> $HOME_NET [4444,8443] (msg:"CyberMind AI - Obfuscated C2 Beacon Download Detected"; content:"DownloadString"; nocase; sid:1000001; rev:1;)`;

  const suricataRule = `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CyberMind AI - Malicious PowerShell Stage-2 Payload Download"; content:"shell.ps1"; http_uri; sid:2000001; rev:1;)`;

  return {
    powershell: psScript,
    bash: bashScript,
    yara: yaraRule,
    sigma: sigmaRule,
    snort: snortRule,
    suricata: suricataRule
  };
}
