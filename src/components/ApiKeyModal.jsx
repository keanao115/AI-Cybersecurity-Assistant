import React from 'react';
import { Key, X, Check } from 'lucide-react';

export default function ApiKeyModal({ apiKey, setApiKey, onClose }) {
  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="glass-panel p-6 rounded-2xl max-w-md w-full border border-cyan-500/30 space-y-4 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="font-bold text-sm text-white flex items-center gap-2 font-mono">
            <Key className="w-4 h-4 text-cyan-400" /> Configure AI API Key
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-300 font-mono">
          Enter your Google Gemini or OpenAI API Key to enable online contextual threat intelligence reasoning. If omitted, CyberMind AI operates using its built-in offline security rules engine.
        </p>

        <input
          type="password"
          placeholder="AIzaSy... / sk-..."
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          className="bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs rounded-xl px-4 py-2.5 w-full focus:outline-none focus:border-cyan-500"
        />

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 font-mono text-xs font-bold hover:bg-cyan-400 transition-all flex items-center gap-1"
          >
            <Check className="w-3.5 h-3.5" /> Save & Close
          </button>
        </div>
      </div>
    </div>
  );
}
