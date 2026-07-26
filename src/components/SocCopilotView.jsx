import React, { useState } from 'react';
import { Bot, CheckSquare, Square, ShieldAlert, ArrowRight, CheckCircle, ShieldCheck } from 'lucide-react';

const PLAYBOOKS = [
  {
    id: 'pb-1',
    title: 'PowerShell & Command Line Audit SOP',
    steps: [
      { id: 1, label: 'Inspect Event ID 4688 Command Line for -enc or DownloadString strings', done: true },
      { id: 2, label: 'Query remote IP addresses against VirusTotal & AbuseIPDB', done: true },
      { id: 3, label: 'Identify parent process hierarchy (cmd.exe / winword.exe / wmiprvse.exe)', done: true },
      { id: 4, label: 'Check endpoint memory dump & running process tree for suspicious processes', done: false },
      { id: 5, label: 'Verify host network isolation policies and endpoint security status', done: false },
    ]
  },
  {
    id: 'pb-2',
    title: 'Local User Account & Privilege Audit SOP',
    steps: [
      { id: 1, label: 'Check Event ID 4720 target user name and subject administrator user', done: true },
      { id: 2, label: 'Audit assigned privilege groups (SeDebugPrivilege, SeTakeOwnershipPrivilege)', done: true },
      { id: 3, label: 'Verify administrative accounts against approved IAM inventory', done: false },
      { id: 4, label: 'Check Domain Controller Kerberos TGT ticket requests & log retention', done: false },
    ]
  }
];

export default function SocCopilotView() {
  const [selectedPlaybook, setSelectedPlaybook] = useState(PLAYBOOKS[0]);
  const [steps, setSteps] = useState(selectedPlaybook.steps);

  const toggleStep = (id) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, done: !s.done } : s));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-cyan-400" />
            SOC Analyst Copilot & Incident Investigation Playbooks
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Guided incident triage playbooks with automated investigation checklists and host isolation triggers.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Playbook list */}
        <div className="space-y-3">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Available Playbooks:</span>
          {PLAYBOOKS.map((pb) => (
            <button
              key={pb.id}
              onClick={() => { setSelectedPlaybook(pb); setSteps(pb.steps); }}
              className={`w-full p-4 rounded-2xl text-left border font-mono transition-all ${
                selectedPlaybook.id === pb.id
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-lg shadow-cyan-500/10'
                  : 'glass-panel text-slate-300 border-slate-800 hover:border-cyan-500/30'
              }`}
            >
              <div className="text-xs font-bold">{pb.title}</div>
              <div className="text-[10px] text-slate-400 mt-1">{pb.steps.length} Step Guided Investigation</div>
            </button>
          ))}
        </div>

        {/* Selected Playbook Step Checklist */}
        <div className="md:col-span-2 glass-panel p-6 rounded-2xl space-y-5">
          <div className="flex items-center justify-between border-b border-slate-900 pb-3">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              {selectedPlaybook.title}
            </h3>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20">
              Active Incident Response
            </span>
          </div>

          <div className="space-y-3">
            {steps.map((step) => (
              <div
                key={step.id}
                onClick={() => toggleStep(step.id)}
                className={`p-3.5 rounded-xl border text-xs font-mono flex items-center gap-3 cursor-pointer transition-all ${
                  step.done
                    ? 'bg-slate-950/60 border-slate-900 text-slate-400 line-through'
                    : 'bg-slate-900/60 border-slate-800 text-slate-200 hover:border-cyan-500/30'
                }`}
              >
                {step.done ? (
                  <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <Square className="w-4 h-4 text-slate-500 shrink-0" />
                )}
                <span>Step {step.id}: {step.label}</span>
              </div>
            ))}
          </div>

          {/* Isolation Action Trigger */}
          <div className="pt-4 border-t border-slate-900 flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Emergency Action Trigger:</span>
            <button className="flex items-center gap-2 px-4 py-2 rounded-xl bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 font-mono text-xs font-bold transition-all">
              <ShieldCheck className="w-4 h-4" /> Isolate Target Host DC-SRV-01
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
