import React, { useState, useEffect } from 'react';
import { Cpu, Zap, Activity, HardDrive } from 'lucide-react';

export default function PipelinePerformanceView() {
  const [stats, setStats] = useState(null);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/pipeline/stats');
      if (res.ok) setStats(await res.json());
    } catch (err) {
      console.warn('[PipelinePerformanceView] Fetch failed:', err);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-cyan-500/20 pb-4">
        <div>
          <h2 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent flex items-center gap-2">
            <Zap className="w-6 h-6 text-cyan-400" /> Pipeline Performance & Ring Buffer Metrics
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time observability into Packet Queue depth, Worker Pool concurrency, and Flow Cache hit rates
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-mono block">Packet Queue Depth</span>
          <span className="text-2xl font-bold font-mono text-cyan-400">{stats?.packetQueueDepth || 0} pkts</span>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-mono block">Worker Pool Active</span>
          <span className="text-2xl font-bold font-mono text-emerald-400">
            {stats?.workerPoolBusyCount || 1} / {stats?.workerPoolTotalCount || 4}
          </span>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-mono block">Flow Cache Hit Rate</span>
          <span className="text-2xl font-bold font-mono text-amber-400">
            {stats?.flowCache?.cacheHitRatePercentage || 100}%
          </span>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-mono block">Avg Latency</span>
          <span className="text-2xl font-bold font-mono text-purple-400">{stats?.averageLatencyMs || 1.2} ms</span>
        </div>
      </div>
    </div>
  );
}
