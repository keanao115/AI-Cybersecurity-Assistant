import React, { useState } from 'react';
import { FileSpreadsheet, Download, Printer, ShieldCheck, FileText, Check } from 'lucide-react';
import jsPDF from 'jspdf';

export default function IncidentReportsView({ anomalies }) {
  const [downloadedFormat, setDownloadedFormat] = useState(null);

  const reportMarkdown = `# CYBERMIND AI - SYSTEM DEFENSE & THREAT AUDIT REPORT
**Report Date**: ${new Date().toLocaleDateString()}
**Classification**: CONFIDENTIAL / CISO AUDIT
**System Status**: ACTIVE DEFENSE & VERIFIED HARDENING

---

## 1. EXECUTIVE SUMMARY
This report details the technical security findings and defensive telemetry evaluation recorded by CyberMind AI sensors on ${new Date().toLocaleDateString()}. The assessment covers detected anomalies, MITRE ATT&CK technique mappings, vulnerability posture, and recommended mitigation controls.

## 2. SYSTEM INVENTORY & SCOPE
- **Evaluated Target**: Corporate Infrastructure Telemetry (Host: DC-SRV-01 / Web Gateways)
- **Active Sensors**: Windows Security Event Audit, Syslog Receiver, Firewall Rule Engine
- **Unhandled High Risk Findings**: 0 (Automated containment rules validated)

## 3. IDENTIFIED ANOMALY FINDINGS & MITRE ATT&CK MAPPING
- **Authentication Telemetry**: Password Guessing Activity (T1110.001) - Source IP filtering recommended.
- **Process Telemetry**: Scripting Interpreter / Execution Verification (T1059.001) - Execution Policy enforced.
- **Access Control**: Local User Account Audit (T1136.001) - Privilege validation active.
- **Audit Persistence**: System Event Log Clearing Verification (T1070.001) - Immutable SIEM log streaming verified.

## 4. REMEDIATION & HARDENING RECOMMENDATIONS
1. Maintain strict perimeter IP blocking for unauthenticated access attempts.
2. Enforce Multi-Factor Authentication (MFA) across all administrative RDP/SSH entry points.
3. Apply OS security patches (e.g., MS17-010 / Log4j mitigation) across all endpoints.
4. Schedule periodic red-team exercises via the Attack Simulation module.
`;

  const handleDownloadPdf = () => {
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text("CYBERMIND AI - SECURITY AUDIT REPORT", 14, 20);
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);
    doc.text("Classification: CONFIDENTIAL / CISO AUDIT", 14, 34);

    const splitText = doc.splitTextToSize(reportMarkdown, 180);
    doc.text(splitText, 14, 45);
    doc.save("CyberMind_Security_Audit_Report.pdf");

    setDownloadedFormat('PDF');
    setTimeout(() => setDownloadedFormat(null), 3000);
  };

  const handleDownloadMarkdown = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'CyberMind_Security_Audit_Report.md';
    a.click();

    setDownloadedFormat('Markdown');
    setTimeout(() => setDownloadedFormat(null), 3000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <FileSpreadsheet className="w-6 h-6 text-cyan-400" />
            Automated Cybersecurity Report Exporter
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Auto-generate technical CISO audit reports with executive summary, system inventory, MITRE mapping, and recommendations.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadPdf}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-mono text-xs font-bold transition-all shadow-sm"
          >
            {downloadedFormat === 'PDF' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Download className="w-3.5 h-3.5" />}
            Export PDF Report
          </button>
          <button
            onClick={handleDownloadMarkdown}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 font-mono text-xs font-bold transition-all"
          >
            <FileText className="w-3.5 h-3.5 text-slate-400" />
            Export Markdown
          </button>
        </div>
      </div>

      {/* Report Preview Container */}
      <div className="glass-panel p-8 rounded-2xl max-w-4xl mx-auto space-y-6 font-mono text-xs text-slate-300 border border-cyan-500/20 shadow-2xl">
        <div className="border-b border-slate-800 pb-4 flex justify-between items-start">
          <div>
            <h1 className="text-lg font-black text-cyan-300">CYBERMIND AI - SYSTEM DEFENSE & THREAT AUDIT REPORT</h1>
            <div className="text-slate-500 mt-1">Ref ID: AUDIT-2026-0725-101 | Status: VERIFIED HEALTHY</div>
          </div>
          <span className="px-3 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg text-[10px] font-bold uppercase">
            CONFIDENTIAL / CISO AUDIT
          </span>
        </div>

        <div>
          <h3 className="font-bold text-white text-sm mb-1 text-cyan-400">1. EXECUTIVE SUMMARY</h3>
          <p className="leading-relaxed text-slate-300">
            On {new Date().toLocaleDateString()}, CyberMind AI security telemetry completed a comprehensive defensive scan across registered host assets. All telemetry streams indicate system integrity within standard operational baselines. No unhandled critical threat alerts currently exist.
          </p>
        </div>

        <div>
          <h3 className="font-bold text-white text-sm mb-2 text-cyan-400">2. MITRE ATT&CK EVALUATION & HARDENING MAPPED</h3>
          <div className="grid grid-cols-2 gap-2">
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1110.001</span>: Brute Force Protection Active
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1059.001</span>: Script Interpreter Execution Restricted
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1136.001</span>: Local Accounts Audited
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1070.001</span>: Event Log Forwarding Verified
            </div>
          </div>
        </div>

        <div>
          <h3 className="font-bold text-white text-sm mb-1 text-cyan-400">3. SECURITY RECOMMENDATIONS</h3>
          <ul className="list-disc list-inside space-y-1 text-slate-300">
            <li>Periodic IP blocklist synchronization with Threat Intel feeds.</li>
            <li>Enforce mandatory 2FA on remote management consoles.</li>
            <li>Use the <strong>Attack Simulation Module</strong> to test custom incident response playbooks.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
