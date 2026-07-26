import React, { useState } from 'react';
import { Network, Play, ShieldAlert, CheckCircle, Terminal, Cpu, Server, Activity, AlertTriangle, Upload, Lock, CheckSquare, RefreshCw, Eye } from 'lucide-react';
import { parseNmapScan } from '../utils/logParsers';

export default function NetworkScannerView({ onScanCompleted }) {
  const [targetIp, setTargetIp] = useState('127.0.0.1');
  const [authorized, setAuthorized] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [showAllPorts, setShowAllPorts] = useState(false);
  const [rawNmapOutput, setRawNmapOutput] = useState('');

  // Handle uploading real Nmap XML or Output file
  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;
      setRawNmapOutput(content);
      const parsed = parseNmapScan(content);
      const resultObj = {
        host: parsed.host,
        os: parsed.os,
        openPorts: parsed.openPorts,
        allResults: parsed.openPorts
      };
      setScanResult(resultObj);
      if (onScanCompleted) onScanCompleted(resultObj);
    };
    reader.readAsText(file);
  };

  // Execute REAL TCP Socket Probe via Node.js backend API (/api/scan)
  const runRealNetSocketScan = async () => {
    if (!authorized) {
      alert("Permission Verification Required: Please confirm you own or have explicit authorization to scan this target.");
      return;
    }

    if (!targetIp.trim()) {
      alert("Please enter a valid IP address (e.g. 127.0.0.1 or your local network IP).");
      return;
    }

    setIsScanning(true);
    setScanResult(null);
    setScanProgress(`Initializing Node.js native TCP socket scanner for target ${targetIp}...`);

    try {
      setScanProgress(`Sending parallel TCP SYN/Connect handshakes to ${targetIp}...`);
      const response = await fetch(`/api/scan?target=${encodeURIComponent(targetIp)}`);
      
      if (!response.ok) {
        throw new Error(`Scan server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setScanProgress('Analyzing discovered service banners and evaluating risk posture...');

      setTimeout(() => {
        const resultObj = {
          host: data.host,
          os: `Node.js Native net.Socket TCP Scanner (Scanned ${data.scannedPortsCount} Ports)`,
          openPorts: data.openPorts,
          allResults: data.allResults
        };
        setScanResult(resultObj);
        if (onScanCompleted) onScanCompleted(resultObj);
        setIsScanning(false);
        setScanProgress('');
      }, 500);
    } catch (err) {
      console.error("Real TCP Scan error:", err);
      alert(`Network Scan Error: ${err.message}. Make sure CyberMind AI dev server is running!`);
      setIsScanning(false);
      setScanProgress('');
    }
  };

  const portsToDisplay = scanResult 
    ? (showAllPorts ? scanResult.allResults : scanResult.openPorts)
    : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Network className="w-6 h-6 text-cyan-400" />
            Real Network Security Scanner & Node.js Telemetry Engine
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Uses Node.js native <code className="text-cyan-300">net.Socket</code> to perform actual TCP connect scans against your laptop or local network IP.
          </p>
        </div>
      </div>

      {/* Target & Authorization Panel */}
      <div className="glass-panel p-5 rounded-2xl space-y-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto flex-1">
            <label className="text-xs font-mono text-slate-300 font-semibold whitespace-nowrap">Target Laptop / IP Address:</label>
            <input
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-sm rounded-xl px-4 py-2 focus:outline-none focus:border-cyan-500 w-full max-w-sm"
              placeholder="e.g. 127.0.0.1, 192.168.1.10"
            />
          </div>

          {/* Import Real Scan File */}
          <div className="flex items-center gap-2 w-full md:w-auto">
            <label className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 cursor-pointer font-mono transition-all">
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              Import Real Nmap (.xml / .txt)
              <input type="file" onChange={handleFileUpload} className="hidden" accept=".xml,.txt,.gnmap" />
            </label>

            <button
              onClick={runRealNetSocketScan}
              disabled={isScanning || !authorized}
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
            >
              {isScanning ? <Activity className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
              {isScanning ? 'Probing Target Ports...' : 'Execute Real TCP Socket Probe'}
            </button>
          </div>
        </div>

        {/* Authorization Mandate Checkbox */}
        <div className="pt-3 border-t border-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <button
            onClick={() => setAuthorized(!authorized)}
            className="flex items-center gap-2 text-xs font-mono text-slate-300 hover:text-white text-left"
          >
            {authorized ? (
              <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <Lock className="w-4 h-4 text-amber-400 shrink-0" />
            )}
            <span>
              <strong>Authorization Verification:</strong> I confirm that I own or have explicit written authorization to scan target <code className="text-cyan-300">{targetIp || 'laptop IP'}</code>.
            </span>
          </button>

          {scanResult && scanResult.allResults && (
            <button
              onClick={() => setShowAllPorts(!showAllPorts)}
              className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 px-2.5 py-1 rounded-lg border border-cyan-500/20 shrink-0"
            >
              <Eye className="w-3.5 h-3.5" />
              {showAllPorts ? "Show Open Ports Only" : "Show All Scanned Ports"}
            </button>
          )}
        </div>
      </div>

      {/* Live Scan Progress */}
      {isScanning && (
        <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/30 flex items-center gap-3 font-mono text-xs text-cyan-300">
          <Activity className="w-4 h-4 animate-spin text-cyan-400" />
          <span>{scanProgress}</span>
        </div>
      )}

      {/* Real Scan Results */}
      {scanResult ? (
        <>
          {/* OS & Target Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400"><Server className="w-5 h-5" /></div>
              <div>
                <div className="text-xs text-slate-400">Target Host</div>
                <div className="text-sm font-bold font-mono text-cyan-300">{scanResult.host}</div>
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400"><Cpu className="w-5 h-5" /></div>
              <div>
                <div className="text-xs text-slate-400">Scanner Engine</div>
                <div className="text-sm font-bold font-mono text-purple-300">{scanResult.os}</div>
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-slate-800 flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400"><CheckCircle className="w-5 h-5" /></div>
              <div>
                <div className="text-xs text-slate-400">Open Ports Found</div>
                <div className="text-sm font-bold font-mono text-emerald-400">{scanResult.openPorts.length} Active Listeners</div>
              </div>
            </div>
          </div>

          {/* Discovered Ports Table */}
          <div className="glass-panel p-5 rounded-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Verified Port Socket Telemetry
              </h3>
              <span className="text-xs font-mono text-slate-400">
                Displaying <strong className="text-cyan-400">{portsToDisplay.length}</strong> ports
              </span>
            </div>

            {portsToDisplay.length === 0 ? (
              <div className="p-6 text-center text-xs font-mono text-slate-400 bg-slate-950 rounded-xl space-y-2">
                <div className="text-emerald-400 font-bold">No open TCP ports detected!</div>
                <p>
                  Target host <code className="text-cyan-300">{scanResult.host}</code> is hardened or protected by a local firewall. Click <strong>"Show All Scanned Ports"</strong> above to inspect closed/filtered port responses.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">PORT</th>
                      <th className="py-2.5 px-3">PROTOCOL</th>
                      <th className="py-2.5 px-3">STATE</th>
                      <th className="py-2.5 px-3">SERVICE TELEMETRY</th>
                      <th className="py-2.5 px-3">RESPONSE TIME (RTT)</th>
                      <th className="py-2.5 px-3">SECURITY NOTES / EVIDENCES</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-900">
                    {portsToDisplay.map((p, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-3 font-bold text-cyan-400">{p.port}</td>
                        <td className="py-3 px-3 uppercase text-slate-400">{p.protocol}</td>
                        <td className="py-3 px-3">
                          <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                            p.state === 'open' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                            p.state === 'filtered' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                            {p.state}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-200">{p.service}</td>
                        <td className="py-3 px-3 text-cyan-300">{p.rtt || 'N/A'}</td>
                        <td className="py-3 px-3 text-slate-400">
                          {p.port === 445 && p.state === 'open' ? (
                            <span className="text-red-400 font-bold flex items-center gap-1">
                              <AlertTriangle className="w-3.5 h-3.5" /> {p.vulns}
                            </span>
                          ) : (
                            p.vulns
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="glass-panel p-8 text-center text-xs font-mono text-slate-400 space-y-2 border border-dashed border-slate-800 rounded-2xl">
          <Network className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-slate-300 font-bold text-sm">Real TCP Socket Scanner Ready</div>
          <p>
            Enter your laptop's IP address (e.g. <code>127.0.0.1</code> or <code>192.168.x.x</code>), check the <strong>Authorization Verification</strong> checkbox, and click <strong>"Execute Real TCP Socket Probe"</strong> to run a native Node.js TCP handshake port audit on your laptop.
          </p>
        </div>
      )}
    </div>
  );
}
