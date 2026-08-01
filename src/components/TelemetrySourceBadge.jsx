import React from 'react';

export default function TelemetrySourceBadge({ provenance, sourceText, className = '' }) {
  if (!provenance && !sourceText) {
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400 border border-slate-700 ${className}`}>
        UNKNOWN SOURCE
      </span>
    );
  }

  const src = provenance?.telemetrySource || sourceText || 'UNKNOWN';
  const isSynthetic = provenance?.isSynthetic || src === 'SYNTHETIC_DEMO';
  const isSeeded = provenance?.isSeeded || src === 'SEEDED_DEMO';

  let badgeLabel = 'UNKNOWN SOURCE';
  let styleClasses = 'bg-slate-800 text-slate-400 border-slate-700';

  if (isSynthetic) {
    badgeLabel = 'DEMO SYNTHETIC';
    styleClasses = 'bg-purple-500/20 text-purple-300 border-purple-500/40';
  } else if (isSeeded) {
    badgeLabel = 'DEMO SEEDED';
    styleClasses = 'bg-amber-500/20 text-amber-300 border-amber-500/40';
  } else {
    switch (src) {
      case 'SYSLOG_COLLECTOR':
        badgeLabel = 'LIVE SYSLOG';
        styleClasses = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
        break;
      case 'WEF_COLLECTOR':
        badgeLabel = 'LIVE WEF';
        styleClasses = 'bg-blue-500/20 text-blue-300 border-blue-500/40';
        break;
      case 'NETFLOW_COLLECTOR':
        badgeLabel = 'LIVE NETFLOW';
        styleClasses = 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
        break;
      case 'PCAP_UPLOAD':
        badgeLabel = 'UPLOADED PCAP';
        styleClasses = 'bg-teal-500/20 text-teal-300 border-teal-500/40';
        break;
      case 'NMAP_IMPORT':
        badgeLabel = 'NMAP IMPORT';
        styleClasses = 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40';
        break;
      case 'API_INGEST':
        badgeLabel = 'API INGEST';
        styleClasses = 'bg-sky-500/20 text-sky-300 border-sky-500/40';
        break;
      default:
        badgeLabel = src.replace('_', ' ');
    }
  }

  const tooltipText = provenance
    ? `Source: ${provenance.telemetrySource}\nCollection: ${provenance.collectionMethod}\nCollector: ${provenance.collectorId || 'N/A'}\nIngested: ${provenance.ingestionTimestamp}\nSynthetic: ${provenance.isSynthetic ? 'Yes' : 'No'}`
    : `Source: ${src}`;

  return (
    <span
      title={tooltipText}
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border font-mono ${styleClasses} ${className}`}
    >
      {badgeLabel}
    </span>
  );
}
