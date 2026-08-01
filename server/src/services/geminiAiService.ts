import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from '@google/generative-ai';

const SOC_SYSTEM_PROMPT = `You are the AI Assistant for the Security Engineering Portfolio Project, a Senior Security Operations Center (SOC) Analyst and Threat Intelligence expert with 15 years of experience.

Your expertise covers:
- MITRE ATT&CK framework (all tactics and techniques)
- Windows Event Log analysis (Event IDs: 4624, 4625, 4688, 4698, 4719, 4720, 1102, etc.)
- Linux audit log analysis (auditd, auth.log, syslog)
- Network traffic analysis (Wireshark, Zeek, Suricata)
- Threat hunting methodologies
- Incident Response (NIST SP 800-61)
- Vulnerability management (CVE/CVSS scoring)
- SIEM correlation rules (Splunk, Elastic, Microsoft Sentinel)
- Malware behavior analysis (static + dynamic)

You ONLY perform DEFENSIVE operations:
- Log analysis and threat detection
- Incident triage and investigation
- Security hardening recommendations  
- YARA/Sigma rule generation for detection
- PowerShell/Bash remediation scripts
- Risk scoring and executive reporting

You NEVER assist with:
- Offensive exploitation or attack tools
- Malware development or C2 infrastructure
- Unauthorized access or credential theft
- Any illegal activity

Format responses with clear sections using markdown. Always reference MITRE ATT&CK techniques (T####.###) when applicable. Be concise but thorough.`;

const SAFETY_SETTINGS = [
  { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
  { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
  { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
  { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
];

export interface ChatMessage {
  role: 'user' | 'model';
  parts: string;
}

export interface ThreatAnalysisContext {
  logs?: any[];
  findings?: any[];
  scan?: any;
  siemEvents?: any[];
  networkFlows?: any[];
  evidenceBundle?: any;
}

let genAI: GoogleGenerativeAI | null = null;

function getGenAI(): GoogleGenerativeAI | null {
  if (!genAI) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return null;
    genAI = new GoogleGenerativeAI(apiKey);
  }
  return genAI;
}

export async function chatWithSocCopilot(
  history: ChatMessage[],
  userMessage: string,
  context?: ThreatAnalysisContext
): Promise<string> {
  const client = getGenAI();

  if (!client) {
    // Graceful fallback — rule-based responses
    return generateFallbackResponse(userMessage);
  }

  try {
    const model = client.getGenerativeModel({
      model: 'gemini-1.5-flash',
      systemInstruction: SOC_SYSTEM_PROMPT,
      safetySettings: SAFETY_SETTINGS,
    });

    // Build context string from live telemetry data
    let contextStr = '';
    if (context) {
      if (context.siemEvents && context.siemEvents.length > 0) {
        const recent = context.siemEvents.slice(0, 5);
        contextStr += `\n\n**Live SIEM Events (last ${recent.length}):**\n`;
        recent.forEach((e: any) => {
          contextStr += `- [${e.severity}] ${e.sourceCategory} | Host: ${e.hostName} | EventID: ${e.eventId} | ${e.summary} | MITRE: ${e.mitreTechnique}\n`;
        });
      }
      if (context.findings && context.findings.length > 0) {
        contextStr += `\n**Vulnerability Findings (${context.findings.length} total):**\n`;
        context.findings.slice(0, 3).forEach((f: any) => {
          contextStr += `- ${f.cveId || 'CVE-UNKNOWN'} | CVSS ${f.cvss || 'N/A'} | ${f.name || f.description || 'Finding'}\n`;
        });
      }
      if (context.scan && context.scan.openPorts) {
        contextStr += `\n**Recent Port Scan — Host ${context.scan.host}:**\n`;
        contextStr += `Open ports: ${context.scan.openPorts.map((p: any) => `${p.port}/${p.protocol}`).join(', ')}\n`;
      }
      if (context.logs && context.logs.length > 0) {
        contextStr += `\n**Ingested Log Events (${context.logs.length} total)**\n`;
      }
    }

    const fullMessage = contextStr
      ? `${userMessage}\n\n---\n*Context from live SOC telemetry:*${contextStr}`
      : userMessage;

    // Build chat history for multi-turn
    const chatHistory = history.map(h => ({
      role: h.role,
      parts: [{ text: h.parts }],
    }));

    const chat = model.startChat({ history: chatHistory });
    const result = await chat.sendMessage(fullMessage);
    return result.response.text();
  } catch (err: any) {
    console.error('[Gemini] API error:', err.message);
    return generateFallbackResponse(userMessage);
  }
}

export async function analyzeLogsWithGemini(telemetry: ThreatAnalysisContext): Promise<{
  riskScore: number;
  postureStatus: 'OPTIMAL' | 'ELEVATED_RISK' | 'ACTION_REQUIRED';
  executiveSummary: string;
  mitreCoverage: Array<{ technique: string; description: string }>;
  prioritizedRemediations: string[];
  aiGenerated: boolean;
}> {
  const client = getGenAI();

  if (!client) {
    return generateFallbackAnalysis(telemetry);
  }

  try {
    const model = client.getGenerativeModel({
      model: 'gemini-1.5-flash',
      systemInstruction: SOC_SYSTEM_PROMPT,
      safetySettings: SAFETY_SETTINGS,
    });

    const logCount = telemetry.logs?.length || 0;
    const openPorts = telemetry.scan?.openPorts?.length || 0;
    const siemCount = telemetry.siemEvents?.length || 0;

    const prompt = `Perform a threat assessment based on this SOC telemetry snapshot. Return a JSON object ONLY with no markdown wrapping:
{
  "riskScore": <0-100 integer>,
  "postureStatus": "OPTIMAL" | "ELEVATED_RISK" | "ACTION_REQUIRED",
  "executiveSummary": "<2-3 sentence executive summary>",
  "mitreCoverage": [{"technique": "T####.###", "description": "<what was detected>"}],
  "prioritizedRemediations": ["<action 1>", "<action 2>", "<action 3>"]
}

Telemetry:
- Log events ingested: ${logCount}
- Open network ports found: ${openPorts}
- Active SIEM alerts: ${siemCount}
${telemetry.siemEvents?.slice(0, 4).map((e: any) => `- SIEM [${e.severity}]: ${e.summary} (${e.mitreTechnique})`).join('\n') || ''}
${telemetry.scan?.openPorts?.map((p: any) => `- Port ${p.port}/${p.protocol}: ${p.service}`).join('\n') || ''}`;

    const result = await model.generateContent(prompt);
    const text = result.response.text().trim();
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      const status = parsed.postureStatus as string;
      const validStatus: 'OPTIMAL' | 'ELEVATED_RISK' | 'ACTION_REQUIRED' =
        (status === 'OPTIMAL' || status === 'ELEVATED_RISK' || status === 'ACTION_REQUIRED')
          ? status : 'ELEVATED_RISK';
      return { ...parsed, postureStatus: validStatus, aiGenerated: true };
    }
    return generateFallbackAnalysis(telemetry);
  } catch (err: any) {
    console.error('[Gemini] Analysis error:', err.message);
    return generateFallbackAnalysis(telemetry);
  }
}

function generateFallbackResponse(input: string): string {
  const lower = input.toLowerCase();
  if (lower.includes('4625') || lower.includes('brute') || lower.includes('logon fail')) {
    return `### 🔍 Event ID 4625 — Failed Logon Analysis\n\n**MITRE ATT&CK**: T1110.001 (Brute Force: Password Guessing)\n\nHigh-volume 4625 events indicate a credential stuffing or password spray attack.\n\n**Immediate Actions:**\n1. Lock the targeted account temporarily and review source IPs\n2. Enable Account Lockout Policy (threshold: 5 attempts, 30-min observation)\n3. Block source IPs at perimeter firewall\n4. Correlate with Event ID 4624 (successful logon) to detect lateral movement\n\n*Note: Connect a Gemini API key in server/.env for AI-powered analysis.*`;
  }
  if (lower.includes('4688') || lower.includes('process') || lower.includes('powershell')) {
    return `### 🔍 Event ID 4688 — Suspicious Process Creation\n\n**MITRE ATT&CK**: T1059.001 (Command and Scripting Interpreter: PowerShell)\n\nEncoded PowerShell (\`-enc\` or \`-EncodedCommand\`) is a red flag for stager payloads.\n\n**Immediate Actions:**\n1. Decode the Base64 command: \`[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<payload>'))\`\n2. Block execution with AppLocker or WDAC policy\n3. Enable PowerShell Script Block Logging (Event ID 4104)\n4. Hunt for child processes spawned by \`powershell.exe\`\n\n*Note: Connect a Gemini API key for AI-powered analysis.*`;
  }
  return `### 🛡️ CyberMind SOC Copilot\n\nQuery received. To enable AI-powered responses, add your **GEMINI_API_KEY** to \`server/.env\`.\n\nCurrently operating in rule-based mode. Ask about:\n- **Windows Event IDs** (4625, 4688, 4720, 1102)\n- **MITRE techniques** (T1059, T1110, T1071)\n- **Log analysis**, **network anomalies**, **incident response**`;
}

function generateFallbackAnalysis(telemetry: ThreatAnalysisContext) {
  const openPorts = telemetry.scan?.openPorts?.length || 0;
  const siemCritical = telemetry.siemEvents?.filter((e: any) => e.severity === 'Critical').length || 0;
  let riskScore = 90;
  riskScore -= openPorts * 5;
  riskScore -= siemCritical * 15;
  riskScore = Math.max(35, Math.min(97, riskScore));
  const postureStatus: 'OPTIMAL' | 'ELEVATED_RISK' | 'ACTION_REQUIRED' =
    riskScore >= 85 ? 'OPTIMAL' : riskScore >= 65 ? 'ELEVATED_RISK' : 'ACTION_REQUIRED';
  return {
    riskScore, postureStatus,
    executiveSummary: `Rule-based analysis evaluated ${telemetry.logs?.length || 0} log events, ${openPorts} open ports, and ${telemetry.siemEvents?.length || 0} SIEM alerts. Add GEMINI_API_KEY for AI-powered analysis.`,
    mitreCoverage: [
      { technique: 'T1110.001', description: 'Password Guessing / Brute Force Monitoring' },
      { technique: 'T1059.001', description: 'PowerShell Encoded Command Detection' },
    ],
    prioritizedRemediations: [
      'Enforce MFA on all privileged accounts.',
      'Restrict SMB (445) and RDP (3389) at perimeter.',
      'Enable PowerShell Script Block Logging.',
    ],
    aiGenerated: false,
  };
}
