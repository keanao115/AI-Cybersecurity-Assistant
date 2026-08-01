import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, Bot, User, Sparkles, Shield, Copy, Check, Zap, AlertCircle } from 'lucide-react';

const API_BASE = '/api';

async function sendChatMessage(history, message, includeContext = true) {
  const res = await fetch(`${API_BASE}/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      history: history.map(m => ({ role: m.sender === 'ai' ? 'model' : 'user', parts: m.text })),
      message,
      includeContext,
    }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const data = await res.json();
  return data.reply;
}

async function checkAiStatus() {
  try {
    const res = await fetch(`${API_BASE}/ai/status`);
    return await res.json();
  } catch {
    return { geminiConfigured: false, mode: 'OFFLINE' };
  }
}

// Simple markdown renderer for AI responses
function MarkdownText({ text }) {
  const lines = text.split('\n');
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (line.startsWith('### ')) return <h3 key={i} className="text-cyan-300 font-bold text-sm mt-2">{line.slice(4)}</h3>;
        if (line.startsWith('## ')) return <h2 key={i} className="text-cyan-200 font-bold mt-2">{line.slice(3)}</h2>;
        if (line.startsWith('**') && line.endsWith('**')) return <p key={i} className="font-bold text-white">{line.slice(2, -2)}</p>;
        if (line.startsWith('- ') || line.startsWith('* ')) {
          return (
            <div key={i} className="flex gap-2 items-start">
              <span className="text-cyan-400 mt-0.5">•</span>
              <span dangerouslySetInnerHTML={{ __html: line.slice(2).replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white">$1</strong>').replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1 rounded text-cyan-300 text-xs">$1</code>') }} />
            </div>
          );
        }
        if (line.startsWith('```')) return null;
        if (line.trim() === '') return <div key={i} className="h-1" />;
        return (
          <p key={i} dangerouslySetInnerHTML={{
            __html: line
              .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white">$1</strong>')
              .replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1 rounded text-cyan-300 text-xs">$1</code>')
              .replace(/\*(T\d{4}[\.\d]*)\*/g, '<span class="text-yellow-400 font-mono text-xs">$1</span>')
          }} />
        );
      })}
    </div>
  );
}

const QUICK_PROMPTS = [
  { label: 'Analyze Live SIEM', prompt: 'Analyze the current live SIEM events and identify the top threats. Include MITRE ATT&CK mapping.', icon: '🔍' },
  { label: 'Windows Event 4625', prompt: 'What does a high volume of Windows Event ID 4625 indicate and how should I respond?', icon: '🪟' },
  { label: 'PowerShell -enc', prompt: 'A process created event shows powershell.exe with -EncodedCommand parameter. What is the threat and remediation?', icon: '⚡' },
  { label: 'Network Anomaly', prompt: 'I see lateral movement on SMB port 445 between internal hosts. What MITRE techniques apply and what should I do?', icon: '🌐' },
  { label: 'Sigma Rule', prompt: 'Write a Sigma rule to detect encoded PowerShell execution (Event ID 4688 with -enc or -EncodedCommand).', icon: '📋' },
  { label: 'IR Playbook', prompt: 'Give me an incident response playbook for a suspected ransomware infection on a Windows domain controller.', icon: '🛡️' },
];

export default function AiChatView() {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: 'Greetings, Commander. I am the **Intelligent Enterprise Security Operations Copilot** — powered by Google Gemini 1.5 Flash.\n\nI have access to your live SOC telemetry: SIEM events, scan results, and vulnerability findings. Ask me anything about your security posture, request YARA/Sigma rules, or get incident response guidance.',
      timestamp: new Date().toISOString(),
    }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [aiStatus, setAiStatus] = useState(null);
  const [copied, setCopied] = useState(null);
  const [includeContext, setIncludeContext] = useState(true);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    checkAiStatus().then(setAiStatus);
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleSend = async (text) => {
    const userText = (text || input).trim();
    if (!userText) return;

    const userMsg = { sender: 'user', text: userText, timestamp: new Date().toISOString() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    try {
      // Only send previous AI turns as history
      const history = messages.filter(m => m.sender !== 'system');
      const reply = await sendChatMessage(history, userText, includeContext);
      setMessages(prev => [...prev, { sender: 'ai', text: reply, timestamp: new Date().toISOString() }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: `⚠️ **Connection Error**\n\nUnable to reach Gemini API: ${err.message}\n\nCheck that the backend server is running and GEMINI_API_KEY is configured in \`server/.env\`.`,
        timestamp: new Date().toISOString(),
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const copyMessage = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopied(idx);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 shrink-0">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <MessageSquare className="w-6 h-6 text-cyan-400" />
            AI SOC Copilot
            {aiStatus?.geminiConfigured && (
              <span className="text-xs font-mono bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 px-2 py-0.5 rounded-full flex items-center gap-1">
                <Zap className="w-3 h-3" /> Gemini 1.5 Flash
              </span>
            )}
            {aiStatus && !aiStatus.geminiConfigured && (
              <span className="text-xs font-mono bg-amber-500/20 border border-amber-500/40 text-amber-400 px-2 py-0.5 rounded-full flex items-center gap-1">
                <AlertCircle className="w-3 h-3" /> Rule-based Fallback
              </span>
            )}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Ask questions, analyze SIEM events, request YARA/Sigma rules, get IR playbooks.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeContext}
              onChange={e => setIncludeContext(e.target.checked)}
              className="accent-cyan-500"
            />
            Include live SOC context
          </label>
          {aiStatus && !aiStatus.geminiConfigured && (
            <div className="text-xs text-amber-400 font-mono bg-amber-500/10 border border-amber-500/30 px-2 py-1 rounded">
              Add GEMINI_API_KEY to server/.env
            </div>
          )}
        </div>
      </div>

      {/* Quick Prompts */}
      <div className="flex flex-wrap gap-2 shrink-0">
        {QUICK_PROMPTS.map((p, i) => (
          <button
            key={i}
            onClick={() => handleSend(p.prompt)}
            disabled={isTyping}
            className="text-xs font-mono bg-slate-900 border border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 px-3 py-1.5 rounded-lg transition-all disabled:opacity-50"
          >
            {p.icon} {p.label}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1 font-mono text-xs">
        {messages.map((m, idx) => (
          <div key={idx} className={`flex items-start gap-3 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
            {m.sender === 'ai' && (
              <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0 mt-0.5">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div className={`relative group max-w-2xl ${m.sender === 'user'
              ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-2xl rounded-tr-sm px-4 py-3'
              : 'bg-slate-950/80 border border-slate-800 text-slate-300 rounded-2xl rounded-tl-sm px-4 py-3 space-y-1'
            }`}>
              {m.sender === 'ai' ? <MarkdownText text={m.text} /> : <p>{m.text}</p>}
              {m.sender === 'ai' && (
                <button
                  onClick={() => copyMessage(m.text, idx)}
                  className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-cyan-400"
                  title="Copy response"
                >
                  {copied === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              )}
              <div className="text-slate-600 text-xs mt-1">{new Date(m.timestamp).toLocaleTimeString()}</div>
            </div>

            {m.sender === 'user' && (
              <div className="w-8 h-8 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {isTyping && (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-2xl rounded-tl-sm px-4 py-3">
              <div className="flex items-center gap-2 text-cyan-400">
                <Sparkles className="w-3 h-3 animate-spin" />
                <span className="text-xs">Gemini is analyzing...</span>
                <span className="flex gap-1">
                  {[0, 1, 2].map(i => (
                    <span key={i} className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
                  ))}
                </span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl flex items-center gap-3 px-3 py-2 shrink-0">
        <Shield className="w-4 h-4 text-slate-600 shrink-0" />
        <input
          type="text"
          placeholder="Ask about threats, request YARA/Sigma rules, analyze Windows Events..."
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !isTyping && handleSend()}
          disabled={isTyping}
          className="bg-transparent text-slate-100 text-xs flex-1 focus:outline-none font-mono placeholder:text-slate-600"
        />
        <button
          onClick={() => handleSend()}
          disabled={isTyping || !input.trim()}
          className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-40 text-white font-mono text-xs font-bold flex items-center gap-2 shadow-lg shadow-cyan-500/25 transition-all"
        >
          <Send className="w-3 h-3" /> Send
        </button>
      </div>
    </div>
  );
}
