import React, { useState, useEffect } from 'react';
import { Search, Upload, ShieldAlert, Globe, Lock, FileText, AlertTriangle, CheckCircle, Download, Network, Share2 } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { fetchPcapSample } from '../services/apiClient';

const SEVERITY_COLOR = { Critical: '#ef4444', High: '#f59e0b', Medium: '#06b6d4', Low: '#10b981' };

async function uploadRealPcapFile(file) {
  const formData = new FormData();
  formData.append('pcapFile', file);
  const res = await fetch('/api/packets/upload', { method: 'POST', body: formData });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Upload failed: ${res.status}`);
  return data.summary;
}

export default function PacketInspectorView() {
  const [pcapData, setPcapData] = useState(null);
  const [activeTab, setActiveTab] = useState('dns');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copiedIoc, setCopiedIoc] = useState(false);

  useEffect(() => {
    setIsAnalyzing(true);
    fetchPcapSample().then(data => {
      if (data) setPcapData(data);
      setIsAnalyzing(false);
    }).catch(() => setIsAnalyzing(false));
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setIsAnalyzing(true);
    try {
      // Send the actual binary file to the real PCAP parser
      const summary = await uploadRealPcapFile(file);
      if (summary) setPcapData(summary);
    } catch (err) {
      console.error('[PCAP Upload]', err.message);
      alert(`PCAP Parse Error: ${err.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleExportIocs = () => {
    if (!pcapData) return;
    const iocExport = {
      pcapFile: pcapData.pcapFileName,
      generatedAt: new Date().toISOString(),
      flaggedThreats: pcapData.flaggedThreats || [],
      suspiciousDns: (pcapData.dnsQueries || []).filter(q => q.isSuspicious || q.dgaScore > 5),
      deprecatedTls: (pcapData.tlsHandshakes || []).filter(t => t.certAlert)
    };
    navigator.clipboard.writeText(JSON.stringify(iocExport, null, 2));
    setCopiedIoc(true);
    setTimeout(() => setCopiedIoc(false), 3000);
  };

  const pieData = pcapData?.protocolDistribution?.map(p => ({ name: p.protocol, value: p.count })) || [];
  const PIE_COLORS = ['#06b6d4', '#8b5cf6', '#f59e0b', '#10b981'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Search className="w-6 h-6 text-cyan-400" />
            Packet Inspector & PCAP Analyzer
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Defensive protocol metadata extraction — DNS queries, TLS SNI fingerprints, HTTP sessions, and threat indicators.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {pcapData && (
            <button onClick={handleExportIocs} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-xs text-cyan-300 font-mono transition-all">
              <Download className="w-3.5 h-3.5 text-cyan-400" /> {copiedIoc ? 'IOCs Copied!' : 'Export IOCs'}
            </button>
          )}
          <label className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 border border-cyan-500/30 text-xs text-white font-mono font-bold cursor-pointer transition-all shadow-md">
            <Upload className="w-4 h-4 text-white" /> Upload PCAP
            <input type="file" onChange={handleFileUpload} className="hidden" accept=".pcap,.pcapng,.cap" />
          </label>
        </div>
      </div>

      {isAnalyzing && (
        <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs font-mono text-cyan-300 flex items-center gap-2 animate-pulse">
          <Search className="w-4 h-4" /> Analyzing PCAP metadata and extracting protocol artifacts…
        </div>
      )}

      {pcapData && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Total Packets', value: pcapData.totalPackets?.toLocaleString(), icon: <FileText className="w-4 h-4" />, color: 'cyan' },
              { label: 'Capture Duration', value: `${pcapData.captureDurationSec}s`, icon: <Globe className="w-4 h-4" />, color: 'blue' },
              { label: 'TLS Handshakes', value: pcapData.tlsHandshakes?.length, icon: <Lock className="w-4 h-4" />, color: 'purple' },
              { label: 'Flagged Threats', value: pcapData.flaggedThreats?.length, icon: <AlertTriangle className="w-4 h-4" />, color: 'red' },
            ].map((card, i) => (
              <div key={i} className={`glass-panel p-4 rounded-2xl border ${card.color === 'red' && card.value > 0 ? 'border-red-500/30' : 'border-slate-800'} flex items-center gap-3`}>
                <div className={`p-2.5 rounded-xl bg-${card.color}-500/10 text-${card.color}-400`}>{card.icon}</div>
                <div>
                  <div className="text-xs text-slate-400">{card.label}</div>
                  <div className={`text-lg font-black font-mono ${card.color === 'red' && card.value > 0 ? 'text-red-400' : 'text-white'}`}>{card.value}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Flagged Threats Banner */}
          {pcapData.flaggedThreats?.length > 0 && (
            <div className="glass-panel p-4 rounded-2xl border border-amber-500/30 space-y-2">
              <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Threat Indicators Extracted from PCAP
              </h3>
              {pcapData.flaggedThreats.map((threat, i) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-slate-950 border border-slate-900">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono"
                    style={{ background: SEVERITY_COLOR[threat.severity] + '20', color: SEVERITY_COLOR[threat.severity] }}>
                    {threat.severity}
                  </span>
                  <div>
                    <div className="text-xs font-bold text-white">{threat.category}</div>
                    <div className="text-xs text-slate-400 font-mono">{threat.details}</div>
                  </div>
                  <span className="ml-auto text-[10px] text-slate-600 font-mono shrink-0">{threat.timestamp}</span>
                </div>
              ))}
            </div>
          )}

          {/* Charts + Tabs */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Protocol Pie */}
            <div className="glass-panel p-5 rounded-2xl">
              <h3 className="font-bold text-sm text-slate-200 mb-4">Protocol Distribution</h3>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={4} dataKey="value">
                    {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#090d16', borderRadius: '8px' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Detail Tab Panel */}
            <div className="lg:col-span-2 glass-panel p-5 rounded-2xl space-y-4">
              <div className="flex gap-2">
                {['dns', 'http', 'tls', 'tcp'].map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold uppercase transition-all ${activeTab === tab ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}>
                    {tab === 'dns' ? 'DNS Queries' : tab === 'http' ? 'HTTP Sessions' : tab === 'tls' ? 'TLS Handshakes' : 'TCP Flows'}
                  </button>
                ))}
              </div>

              <div className="overflow-x-auto text-xs font-mono max-h-64 overflow-y-auto">
                {activeTab === 'dns' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">Time</th><th className="py-2 px-2">Client</th><th className="py-2 px-2">Query Domain</th><th className="py-2 px-2">DGA Score</th><th className="py-2 px-2">Resolved IP</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.dnsQueries || []).map((r, i) => (
                        <tr key={i} className={`hover:bg-slate-900/40 ${r.isSuspicious || r.dgaScore > 5 ? 'bg-red-500/5' : ''}`}>
                          <td className="py-2 px-2 text-slate-500">{r.timestamp}</td>
                          <td className="py-2 px-2 text-slate-300">{r.clientIp}</td>
                          <td className={`py-2 px-2 font-bold ${r.isSuspicious ? 'text-red-400' : 'text-cyan-300'}`}>{r.queryDomain}</td>
                          <td className="py-2 px-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${r.dgaScore > 5 ? 'bg-red-500/20 text-red-400 font-bold' : 'bg-slate-900 text-slate-400'}`}>
                              {r.dgaScore ? `${r.dgaScore}/10` : '1.0/10'}
                            </span>
                          </td>
                          <td className="py-2 px-2 text-slate-300">{r.resolvedIp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {activeTab === 'http' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">Time</th><th className="py-2 px-2">Method</th><th className="py-2 px-2">Host</th><th className="py-2 px-2">URI</th><th className="py-2 px-2">Status</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.httpSessions || []).map((r, i) => (
                        <tr key={i} className={`hover:bg-slate-900/40 ${r.host.includes('malicious') || r.isCleartextAuth ? 'bg-red-500/5' : ''}`}>
                          <td className="py-2 px-2 text-slate-500">{r.timestamp}</td>
                          <td className="py-2 px-2"><span className="px-1.5 rounded bg-cyan-500/10 text-cyan-400">{r.method}</span></td>
                          <td className={`py-2 px-2 font-bold ${r.host.includes('malicious') ? 'text-red-400' : 'text-slate-200'}`}>{r.host}</td>
                          <td className="py-2 px-2 text-slate-400 truncate max-w-[120px]">{r.uri}</td>
                          <td className="py-2 px-2 text-emerald-400">{r.statusCode}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {activeTab === 'tls' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">Time</th><th className="py-2 px-2">Client IP</th><th className="py-2 px-2">SNI</th><th className="py-2 px-2">TLS Version</th><th className="py-2 px-2">Cipher Suite</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.tlsHandshakes || []).map((r, i) => (
                        <tr key={i} className={`hover:bg-slate-900/40 ${r.certAlert ? 'bg-amber-500/5' : ''}`}>
                          <td className="py-2 px-2 text-slate-500">{r.timestamp}</td>
                          <td className="py-2 px-2 text-slate-300">{r.clientIp}</td>
                          <td className="py-2 px-2 text-cyan-300 font-bold">{r.serverSni}</td>
                          <td className={`py-2 px-2 text-xs ${r.certAlert ? 'text-amber-400 font-bold' : 'text-emerald-400'}`}>
                            {r.tlsVersion} {r.certAlert && `[${r.certAlert}]`}
                          </td>
                          <td className="py-2 px-2 text-slate-400 truncate max-w-[160px]">{r.cipherSuite}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {activeTab === 'tcp' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">Stream</th><th className="py-2 px-2">Src IP:Port</th><th className="py-2 px-2">Dst IP:Port</th><th className="py-2 px-2">State</th><th className="py-2 px-2">Payload Preview</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.tcpFlows || []).map((r, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="py-2 px-2 text-cyan-400">Stream #{r.streamId}</td>
                          <td className="py-2 px-2 text-slate-300">{r.srcIp}:{r.srcPort}</td>
                          <td className="py-2 px-2 text-slate-300">{r.destIp}:{r.destPort}</td>
                          <td className="py-2 px-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${r.state === 'ESTABLISHED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                              {r.state}
                            </span>
                          </td>
                          <td className="py-2 px-2 text-slate-400 truncate max-w-[180px]">{r.payloadPreview || 'Data Stream'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
