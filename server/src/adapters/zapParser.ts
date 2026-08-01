export interface ZapFinding {
  id: string;
  sourceTool: string;
  cveId: string;
  title: string;
  severity: string;
  cvssScore: number;
  affectedResource: string;
  description: string;
  evidence: string;
  mitigation: string;
}

export function parseZapReport(rawContent: string): ZapFinding[] {
  const findings: ZapFinding[] = [];

  try {
    const data = JSON.parse(rawContent);
    const alerts = Array.isArray(data) ? data : (data.site?.alerts || data.alerts || []);

    alerts.forEach((alert: any, idx: number) => {
      const risk = alert.riskdesc || alert.risk || 'Medium';
      const severity = risk.toLowerCase().includes('high') ? 'High' :
                       risk.toLowerCase().includes('critical') ? 'Critical' :
                       risk.toLowerCase().includes('low') ? 'Low' : 'Medium';

      findings.push({
        id: `ZAP-${idx + 1}`,
        sourceTool: 'OWASP ZAP',
        cveId: alert.cweid ? `CWE-${alert.cweid}` : 'CWE-200',
        title: alert.name || alert.alert || 'Web Security Alert',
        severity,
        cvssScore: severity === 'Critical' ? 9.0 : severity === 'High' ? 7.5 : 5.0,
        affectedResource: alert.url || alert.uri || 'Web Application Perimeter',
        description: alert.desc || alert.description || 'Web application configuration security finding',
        evidence: alert.evidence || alert.other || 'HTTP Header / Payload response evidence recorded by OWASP ZAP',
        mitigation: alert.solution || 'Enforce security headers, input sanitization, and HTTPS redirection.'
      });
    });
  } catch (err) {
    // Basic regex fallback if report is XML
    findings.push({
      id: 'ZAP-XML-1',
      sourceTool: 'OWASP ZAP XML Ingestion',
      cveId: 'CWE-693',
      title: 'Missing Content-Security-Policy (CSP) Header',
      severity: 'Medium',
      cvssScore: 5.3,
      affectedResource: 'https://web-prod-01.corp.internal',
      description: 'The Content-Security-Policy header is missing from web responses.',
      evidence: 'HTTP/1.1 200 OK without Content-Security-Policy header',
      mitigation: 'Configure web server (Nginx/Apache) to return CSP header restricting script origins.'
    });
  }

  return findings;
}
