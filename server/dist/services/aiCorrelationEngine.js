import { getSiemEvents } from './siemCollectorService.js';
import { getLiveNetworkFlows } from './networkFlowService.js';
import { memoryDb } from '../db/client.js';
export function evaluateMultiVectorCorrelation() {
    const siemEvents = getSiemEvents();
    const flows = getLiveNetworkFlows();
    const findings = memoryDb.findings;
    const endpointCount = siemEvents.filter(e => ['Windows_WEF', 'Linux_Auditd', 'Sysmon', 'Wazuh', 'CrowdStrike', 'Defender'].includes(e.sourceCategory)).length;
    const networkFlowCount = flows.length;
    const vulnerabilityCount = findings.length;
    const criticalEvents = siemEvents.filter(e => e.severity === 'Critical');
    const highEvents = siemEvents.filter(e => e.severity === 'High');
    const anomalousFlows = flows.filter(f => f.anomalyFlag);
    // Dynamic risk calculation
    let riskScore = 96;
    riskScore -= criticalEvents.length * 15;
    riskScore -= highEvents.length * 8;
    riskScore -= anomalousFlows.length * 10;
    riskScore -= Math.min(20, vulnerabilityCount * 4);
    riskScore = Math.max(25, Math.min(99, riskScore));
    const overallThreatLevel = riskScore < 60 ? 'CRITICAL_ALERT' : riskScore < 80 ? 'ELEVATED_THREAT' : 'STABLE_DEFENSE';
    // Build dynamic attack timeline from live telemetry
    const timeline = [];
    siemEvents.slice(0, 5).forEach(e => {
        let stage = 'Initial Access';
        if (e.mitreTechnique.includes('T1059') || e.mitreTechnique.includes('SUDO'))
            stage = 'Execution';
        else if (e.mitreTechnique.includes('T1548') || e.mitreTechnique.includes('T1098'))
            stage = 'Privilege Escalation';
        else if (e.mitreTechnique.includes('T1071') || e.mitreTechnique.includes('C2'))
            stage = 'Command and Control';
        else if (e.mitreTechnique.includes('T1078') || e.mitreTechnique.includes('Lateral'))
            stage = 'Lateral Movement';
        timeline.push({
            time: new Date(e.timestamp).toLocaleTimeString(),
            stage,
            source: `${e.sourceCategory.replace('_', ' ')} (${e.hostName})`,
            headline: e.summary,
            mitreId: e.mitreTechnique.split(' ')[0] || 'T1071',
            confidenceScore: e.severity === 'Critical' ? 98 : e.severity === 'High' ? 90 : 75
        });
    });
    // Dynamic Playbook Recommendations
    const socAnalystPlaybook = [];
    if (anomalousFlows.length > 0) {
        const anomalousIp = anomalousFlows[0].srcIp === '192.168.1.105' ? '185.220.101.5' : anomalousFlows[0].srcIp;
        socAnalystPlaybook.push(`Apply immediate perimeter firewall block for suspicious remote IP ${anomalousIp}.`);
    }
    if (criticalEvents.length > 0) {
        const targetHost = criticalEvents[0].hostName;
        socAnalystPlaybook.push(`Isolate host ${targetHost} using EDR network containment policy.`);
        socAnalystPlaybook.push(`Force password reset & invalidate active OAuth tokens for affected users on ${targetHost}.`);
    }
    else {
        socAnalystPlaybook.push('Perform routine SIEM audit & verify EDR agent heartbeat status on all endpoints.');
    }
    socAnalystPlaybook.push('Cross-reference active DNS query logs with threat intelligence feeds (AlienVault OTX / MISP).');
    socAnalystPlaybook.push('Trigger automated PDF Executive Security Audit Report generation for compliance log.');
    return {
        compositeRiskScore: riskScore,
        overallThreatLevel,
        timeline,
        correlatedVectors: {
            endpointCount,
            networkFlowCount,
            vulnerabilityCount,
            siemEventCount: siemEvents.length
        },
        socAnalystPlaybook
    };
}
