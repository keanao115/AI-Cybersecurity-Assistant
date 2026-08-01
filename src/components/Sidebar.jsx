import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Network,
  Bug,
  FileSpreadsheet,
  Grid,
  Database,
  Zap,
  Bot,
  BookOpen,
  MessageSquare,
  Settings,
  Activity,
  Search,
  Radar,
  Shield,
  Server
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navGroups = [
    {
      label: 'SOC NAVIGATION',
      items: [
        { id: 'dashboard', label: '首頁 Dashboard', icon: LayoutDashboard },
        { id: 'threat', label: 'Threat Analysis', icon: ShieldAlert },
        { id: 'log', label: 'Log Analyzer', icon: FileText },
        { id: 'network', label: 'Network Scanner', icon: Network },
        { id: 'vuln', label: 'Vulnerability Scanner', icon: Bug },
        { id: 'reports', label: 'Incident Reports', icon: FileSpreadsheet },
        { id: 'mitre', label: 'MITRE ATT&CK', icon: Grid },
        { id: 'ioc', label: 'IOC Database', icon: Database },
      ]
    },
    {
      label: 'LIVE MONITORING & TELEMETRY',
      items: [
        { id: 'collectors', label: 'Collector Management', icon: Server, badge: 'PROD' },
        { id: 'packet-capture', label: 'Live Packet Capture', icon: Activity, badge: 'NPCAP' },
        { id: 'zeek-suricata', label: 'Zeek & Suricata IDS', icon: Shield, badge: 'EVE' },
        { id: 'pipeline-performance', label: 'Pipeline Performance', icon: Zap, badge: 'METRICS' },
        { id: 'investigation-timeline', label: 'Evidence Timeline', icon: Radar, badge: 'AI' },
        { id: 'live-network', label: 'Live Network Monitor', icon: Activity },
        { id: 'packet-inspector', label: 'Packet Inspector', icon: Search },
        { id: 'asset-discovery', label: 'Asset Discovery', icon: Radar },
        { id: 'siem-console', label: 'SIEM Event Console', icon: Shield },
      ]
    },
    {
      label: 'AI & SIMULATION',
      items: [
        { id: 'simulation', label: '攻擊模擬 (Simulation)', icon: Zap, highlight: true },
        { id: 'copilot', label: 'SOC Copilot (Playbooks)', icon: Bot, highlight: true },
        { id: 'rag', label: 'RAG 知識庫 (Knowledge)', icon: BookOpen, highlight: true },
        { id: 'chat', label: 'AI Chat Assistant', icon: MessageSquare },
        { id: 'settings', label: 'Settings & Profile', icon: Settings },
      ]
    }
  ];

  return (
    <aside className="w-64 border-r border-cyan-500/15 bg-slate-950/60 backdrop-blur-xl flex flex-col justify-between py-4 shrink-0 overflow-y-auto">
      <div className="space-y-4 px-3">
        {navGroups.map((group) => (
          <div key={group.label}>
            <div className="px-3 py-2 text-[10px] font-mono font-semibold text-slate-500 uppercase tracking-widest">
              {group.label}
            </div>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all duration-200 group ${
                      isActive
                        ? 'bg-gradient-to-r from-cyan-500/20 to-blue-600/10 text-cyan-300 border border-cyan-500/30 shadow-md shadow-cyan-500/10'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                        {item.badge}
                      </span>
                    )}
                    {item.highlight && !item.badge && (
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                        FEATURE
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Footer info */}
      <div className="px-4 pt-4 border-t border-slate-900 text-[11px] text-slate-500 font-mono">
        <div className="flex justify-between items-center mb-1">
          <span>Security Score</span>
          <span className="text-emerald-400 font-bold">94 / 100</span>
        </div>
        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
          <div className="bg-gradient-to-r from-emerald-500 to-cyan-400 h-full w-[94%] rounded-full"></div>
        </div>
      </div>
    </aside>
  );
}
