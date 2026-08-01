import { parseNmapTelemetry } from './adapters/nmapParser.js';
import { parseSuricataEveJson } from './adapters/suricataParser.js';
import { parseWindowsLogTelemetry } from './adapters/windowsLogParser.js';
import { parseLinuxLogTelemetry } from './adapters/linuxLogParser.js';
import { correlateSoftwareVulnerabilities } from './services/vulnerabilityService.js';
import { generateDefensiveAiAnalysis } from './services/aiAnalysisService.js';
import { createCisoAuditPdfReport } from './services/pdfReportService.js';
console.log('--- RUNNING SOC BACKEND ADAPTER & SERVICE VERIFICATION TESTS ---');
// Test 1: Nmap Parser
const nmapXml = `<nmaprun><host><address addr="192.168.1.10"/><osmatch name="Windows Server 2022"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows SMB"/></port></ports></host></nmaprun>`;
const parsedNmap = parseNmapTelemetry(nmapXml);
console.assert(parsedNmap.host === '192.168.1.10', 'Nmap host parsing failed');
console.assert(parsedNmap.openPorts.length === 1, 'Nmap open port count failed');
console.log('✓ Nmap Adapter Test Passed');
// Test 2: Suricata Parser
const eveJson = `{"timestamp":"2026-07-27T10:00:00Z","event_type":"alert","src_ip":"192.168.1.105","dest_ip":"185.220.101.5","alert":{"signature":"ET MALWARE Cobalt Strike Beacon","category":"Trojan"}}`;
const parsedEve = parseSuricataEveJson(eveJson);
console.assert(parsedEve.length === 1, 'Suricata parsing failed');
console.assert(parsedEve[0].category === 'Trojan', 'Suricata category extraction failed');
console.log('✓ Suricata EVE Adapter Test Passed');
// Test 3: Windows Event Parser
const winXml = `<Event><System><EventID>4625</EventID><Computer>DC-SRV-01</Computer></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="IpAddress">192.168.1.155</Data></EventData></Event>`;
const parsedWin = parseWindowsLogTelemetry(winXml);
console.assert(parsedWin[0].eventId === '4625', 'Windows Event ID parsing failed');
console.assert(parsedWin[0].user === 'Administrator', 'Windows User parsing failed');
console.log('✓ Windows Event Adapter Test Passed');
// Test 4: Linux Syslog Parser
const linuxLog = `Jul 25 14:10:01 web-prod-01 sshd[14201]: Failed password for invalid user admin from 185.220.101.5 port 54221 ssh2`;
const parsedLnx = parseLinuxLogTelemetry(linuxLog);
console.assert(parsedLnx[0].action === 'SSH_FAILED_LOGIN', 'Linux Syslog action failed');
console.log('✓ Linux Syslog Adapter Test Passed');
// Test 5: Vulnerability Correlation
correlateSoftwareVulnerabilities([{ name: 'Log4j', version: '2.14.1', host: '192.168.1.50', port: 8080 }])
    .then(vulns => {
    console.assert(vulns[0].cveId === 'CVE-2021-44228', 'Log4j CVE correlation failed');
    console.log('✓ Passive Vulnerability Correlation Test Passed');
});
// Test 6: AI Threat Synthesis
const aiResult = generateDefensiveAiAnalysis({ logs: parsedWin, scan: parsedNmap });
console.assert(aiResult.riskScore > 0, 'AI risk score generation failed');
console.log('✓ Defensive AI Analysis Service Test Passed');
// Test 7: PDF Generator
const pdfBuffer = createCisoAuditPdfReport({ title: 'TEST AUDIT', riskScore: 94 });
console.assert(pdfBuffer.length > 0, 'PDF report buffer generation failed');
console.log('✓ CISO PDF Report Service Test Passed');
console.log('--- ALL SOC BACKEND UNIT TESTS SUCCESSFUL ---');
