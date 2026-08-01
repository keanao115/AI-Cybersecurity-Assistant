import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { usePlatformMode } from '../contexts/PlatformModeContext';

export default function DemoWarningBanner() {
  const { platformMode, syntheticDataEnabled, seedDataEnabled } = usePlatformMode();

  if (platformMode !== 'DEMO') return null;

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 py-2 text-xs text-amber-300 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
        <span className="font-semibold">CONTROLLED DEMONSTRATION ENVIRONMENT:</span>
        <span className="text-amber-200/80">
          This mode contains {syntheticDataEnabled ? 'simulated real-time flows' : ''}{' '}
          {syntheticDataEnabled && seedDataEnabled ? 'and' : ''}{' '}
          {seedDataEnabled ? 'seeded demo assets' : ''}. Events must not be treated as evidence of actual compromise.
        </span>
      </div>

      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
        DEMO MODE
      </span>
    </div>
  );
}
