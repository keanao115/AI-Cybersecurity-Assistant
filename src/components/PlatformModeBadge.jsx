import React from 'react';
import { ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';
import { usePlatformMode } from '../contexts/PlatformModeContext';

export default function PlatformModeBadge() {
  const { platformMode, runtimeModeSwitchAllowed, switchMode, loading } = usePlatformMode();

  if (loading) {
    return (
      <div className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 text-slate-400 rounded-full text-xs font-semibold border border-slate-700">
        <RefreshCw className="w-3 h-3 animate-spin" /> Mode: Loading...
      </div>
    );
  }

  const isLive = platformMode === 'LIVE';

  return (
    <div className="flex items-center gap-2">
      <div
        title={
          isLive
            ? 'LIVE MODE: Only genuine collected, received, or uploaded telemetry is displayed. Synthetic generation disabled.'
            : 'DEMO MODE: Environment contains simulated or seeded telemetry for demonstration purposes.'
        }
        className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold border shadow-sm transition-all ${
          isLive
            ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-emerald-950/20'
            : 'bg-amber-500/15 text-amber-400 border-amber-500/40 shadow-amber-950/20 animate-pulse'
        }`}
      >
        {isLive ? (
          <>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>LIVE MODE</span>
          </>
        ) : (
          <>
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>DEMO MODE</span>
          </>
        )}
      </div>

      {runtimeModeSwitchAllowed && (
        <button
          onClick={() => switchMode(isLive ? 'DEMO' : 'LIVE')}
          className="text-[11px] font-semibold text-slate-400 hover:text-cyan-400 underline underline-offset-2 transition-colors px-1"
        >
          {isLive ? 'Switch to Demo' : 'Switch to Live'}
        </button>
      )}
    </div>
  );
}
