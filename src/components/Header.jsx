import React from 'react';
import { Shield, Key, Sparkles, Activity, User, Bell } from 'lucide-react';

export default function Header({ apiKey, setApiKey, setShowApiModal }) {
  return (
    <header className="h-16 border-b border-cyan-500/15 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-40 px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20">
          <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-extrabold text-lg tracking-wider bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent">
              CyberMind AI
            </h1>
            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              ENTERPRISE v2.5
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono">Autonomous Cyber Threat Intelligence & SOC Copilot</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Status indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          AI Engine: Online (Rule + LLM)
        </div>

        <button
          onClick={() => setShowApiModal(true)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-xs text-cyan-300 transition-all font-mono shadow-sm hover:border-cyan-400"
        >
          <Key className="w-3.5 h-3.5 text-cyan-400" />
          {apiKey ? "API Key Set" : "Configure AI Key"}
        </button>

        <div className="flex items-center gap-2 border-l border-slate-800 pl-4">
          <div className="w-8 h-8 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold text-xs">
            SOC
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-xs font-semibold text-slate-200">Security Admin</div>
            <div className="text-[10px] text-slate-400">SOC Tier-3 Analyst</div>
          </div>
        </div>
      </div>
    </header>
  );
}
