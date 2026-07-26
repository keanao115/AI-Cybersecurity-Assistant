// RAG Knowledge Base Database & Search Engine

export const RAG_KNOWLEDGE_BASE = [
  {
    id: "NIST-800-61",
    category: "Standard",
    title: "NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide",
    summary: "Standard framework for incident response lifecycle: Preparation, Detection & Analysis, Containment Eradication & Recovery, Post-Incident Activity.",
    content: "Containment strategies vary by incident type (e.g. isolating endpoints, disabling compromised user accounts, blocking IP ranges at perimeter firewall). Eradication includes deleting malware, disabling compromised accounts, and closing vulnerabilities."
  },
  {
    id: "WIN-4625",
    category: "Windows Event",
    title: "Event ID 4625: An account failed to log on",
    summary: "Generated on domain controllers or local workstations when a user attempt fails due to bad credentials, locked account, or expired login.",
    content: "Key fields to audit: TargetUserName, WorkstationName, IpAddress, FailureReason (0xC000006A = bad password, 0xC0000072 = account disabled, 0xC0000234 = account locked out). High frequency indicates RDP or SMB brute force attacks."
  },
  {
    id: "WIN-4688",
    category: "Windows Event",
    title: "Event ID 4688: A new process has been created",
    summary: "Logs process execution details. Extremely valuable when Command Line Auditing is enabled via GPO.",
    content: "Look for suspicious parent-child process relationships (e.g., cmd.exe launching powershell.exe, winword.exe launching cmd.exe, wmiprvse.exe launching powershell.exe with -enc or -nop)."
  },
  {
    id: "MITRE-T1110",
    category: "MITRE ATT&CK",
    title: "T1110: Brute Force",
    summary: "Adversaries may use brute force tactics to gain access to accounts when passwords are unknown.",
    content: "Techniques: T1110.001 Password Guessing, T1110.002 Password Cracking, T1110.003 Password Spraying, T1110.004 Credential Stuffing. Mitigation: Multi-Factor Authentication (MFA), account lockout threshold."
  },
  {
    id: "MITRE-T1059",
    category: "MITRE ATT&CK",
    title: "T1059: Command and Scripting Interpreter",
    summary: "Adversaries may abuse command and script interpreters to execute arbitrary commands or malicious stagers.",
    content: "Sub-techniques: T1059.001 PowerShell, T1059.003 Windows Command Shell, T1059.004 Unix Shell. Mitigation: Script Block Logging, Constrained Language Mode, AMSI."
  },
  {
    id: "OWASP-A01",
    category: "OWASP Top 10",
    title: "A01:2021 - Broken Access Control",
    summary: "Failures that allow users to act outside of their intended permissions.",
    content: "Examples: Elevation of privilege, bypassing access checks by modifying URL or request state, viewing someone else's account. Mitigation: Enforce least privilege, disable directory listing."
  },
  {
    id: "OWASP-A03",
    category: "OWASP Top 10",
    title: "A03:2021 - Injection (SQLi, XSS, Command)",
    summary: "User-supplied data is not validated, filtered, or sanitized by the application before execution.",
    content: "SQL Injection occurs when untrusted input is concatenated into dynamic SQL queries. Mitigation: Parameterized queries / Prepared statements, Input validation regex."
  }
];

export function searchRagKnowledge(query) {
  if (!query || query.trim() === "") return RAG_KNOWLEDGE_BASE;
  const q = query.toLowerCase();
  return RAG_KNOWLEDGE_BASE.filter(item => 
    item.title.toLowerCase().includes(q) ||
    item.summary.toLowerCase().includes(q) ||
    item.category.toLowerCase().includes(q) ||
    item.content.toLowerCase().includes(q)
  );
}
