import React from 'react';
import { Radio, ShieldAlert, ArrowRight, Play } from 'lucide-react';
import { usePlatformMode } from '../contexts/PlatformModeContext';

export default function LiveEmptyState({
  title = 'No live telemetry received',
  description = 'The platform is in LIVE mode. Configure a Syslog generator, Windows Event Forwarder (WEF), NetFlow exporter, or upload an authorized PCAP file to begin monitoring.',
  suggestedAction = 'Send events via syslog logger on port 5514 or upload PCAP via Packet Inspector.',
}) {
  const { runtimeModeSwitchAllowed, switchMode } = usePlatformMode();

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center max-w-xl mx-auto space-y-4 my-8">
      <div className="w-12 h-12 rounded-full bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto text-cyan-400">
        <Radio className="w-6 h-6 animate-pulse" />
      </div>

      <div className="space-y-1">
        <h3 className="text-lg font-bold text-slate-100">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed">{description}</p>
      </div>

      <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-[11px] text-slate-300 font-mono flex items-center gap-2 justify-center">
        <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
        <span>{suggestedAction}</span>
      </div>

      {runtimeModeSwitchAllowed && (
        <div className="pt-2">
          <button
            onClick={() => switchMode('DEMO')}
            className="inline-flex items-center gap-2 px-4 py-2 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/40 rounded-lg text-xs font-semibold transition-all"
          >
            <Play className="w-3.5 h-3.5" /> Switch to Demo Mode for Simulated Scenarios
          </button>
        </div>
      )}
    </div>
  );
}
