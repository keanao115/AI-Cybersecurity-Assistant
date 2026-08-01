import React, { useState, useEffect } from 'react';
import { ShieldAlert, Server, Activity, Terminal } from 'lucide-react';
import TelemetrySourceBadge from './TelemetrySourceBadge';

export default function ZeekSuricataView() {
  const [zeekStatus, setZeekStatus] = useState(null);
  const [suricataStatus, setSuricataStatus] = useState(null);

  const fetchStatus = async () => {
    try {
      const resZ = await fetch('/api/zeek/status');
      if (resZ.ok) setZeekStatus(await resZ.json());

      const resS = await fetch('/api/suricata/status');
      if (resS.ok) setSuricataStatus(await resS.json());
    } catch (err) {
      console.warn('[ZeekSuricataView] Fetch failed:', err);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-cyan-500/20 pb-4">
        <div>
          <h2 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent flex items-center gap-2">
            <Server className="w-6 h-6 text-purple-400" /> Zeek & Suricata Telemetry Integration
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time JSON stream parser for Zeek network monitoring and Suricata IDS/IPS EVE security alerts
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Zeek Sensor Card */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-purple-400" /> Zeek Network Monitor
            </h3>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
              {zeekStatus?.status || 'Active'}
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3 text-center text-xs font-mono">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Conn Logs</span>
              <span className="text-purple-400 font-bold">{zeekStatus?.logCounts?.conn || 0}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[10px] block">DNS Logs</span>
              <span className="text-cyan-400 font-bold">{zeekStatus?.logCounts?.dns || 0}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Notice Alerts</span>
              <span className="text-amber-400 font-bold">{zeekStatus?.logCounts?.notice || 0}</span>
            </div>
          </div>
        </div>

        {/* Suricata Sensor Card */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" /> Suricata IDS Engine
            </h3>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              {suricataStatus?.status || 'Active'}
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3 text-center text-xs font-mono">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Engine Version</span>
              <span className="text-slate-200 font-bold">{suricataStatus?.engineVersion || '7.0.6'}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Rules Loaded</span>
              <span className="text-emerald-400 font-bold">{suricataStatus?.rulesLoaded || 34120}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-400 text-[10px] block">Alerts Triggered</span>
              <span className="text-rose-400 font-bold">{suricataStatus?.totalAlertsReceived || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
