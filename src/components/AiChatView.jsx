import React, { useState } from 'react';
import { MessageSquare, Send, Bot, User, Sparkles, Terminal, Copy, Check } from 'lucide-react';

export default function AiChatView({ apiKey }) {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: 'Greetings, Commander. I am CyberMind AI Security Copilot. Ask me any question regarding Windows Event logs, Linux Auth logs, Firewall rules, or request auto-generated mitigation scripts.'
    }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  const handleSend = () => {
    if (!input.trim()) return;

    const userMsg = { sender: 'user', text: input };
    setMessages(prev => [...prev, userMsg]);
    const currentInput = input;
    setInput('');
    setIsTyping(true);

    setTimeout(() => {
      let aiResponseText = '';
      const lower = currentInput.toLowerCase();

      if (lower.includes('windows event') || lower.includes('suspicious') || lower.includes('4625') || lower.includes('4688')) {
        aiResponseText = `### 🔍 Windows Event ID Analysis
**Event ID 4688** with Base64 encoded PowerShell (\`-enc\`) indicates a Cobalt Strike or Empire stager payload attempting stage-2 web download.

#### 🛡️ Threat Breakdown:
- **MITRE ATT&CK**: T1059.001 (Command and Scripting Interpreter: PowerShell)
- **Threat Level**: Critical (9.8/10)
- **Remediation**: Run PowerShell script \`Stop-Process -Name powershell -Force\` and block remote C2 IP on Windows Firewall.`;
      } else if (lower.includes('powershell') || lower.includes('block') || lower.includes('script')) {
        aiResponseText = `Here is your custom PowerShell remediation script:

\`\`\`powershell
# CyberMind AI Custom Firewall & User Mitigation
New-NetFirewallRule -DisplayName "CyberMind-Block-C2" -Direction Inbound -Action Block -RemoteAddress "185.220.101.5"
Disable-LocalUser -Name "shadow_admin" -ErrorAction SilentlyContinue
Stop-Process -Name powershell -Force
\`\`\``;
      } else {
        aiResponseText = `Based on CyberMind RAG Security Knowledge Base (NIST SP 800-61 & MITRE ATT&CK), the anomaly detected on host DC-SRV-01 is consistent with credential harvesting and lateral movement. Recommended action: Isolate host VLAN and rotate Domain Admin credentials.`;
      }

      setMessages(prev => [...prev, { sender: 'ai', text: aiResponseText }]);
      setIsTyping(false);
    }, 800);
  };

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-140px)]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 shrink-0">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <MessageSquare className="w-6 h-6 text-cyan-400" />
            CyberMind AI Chat Assistant (Security Copilot)
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Ask questions, query incident logs, request custom YARA/Sigma/PowerShell rules.
          </p>
        </div>
      </div>

      {/* Messages area */}
      <div className="flex-1 glass-panel p-5 rounded-2xl overflow-y-auto space-y-4 font-mono text-xs">
        {messages.map((m, idx) => (
          <div key={idx} className={`flex items-start gap-3 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
            {m.sender === 'ai' && (
              <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div className={`p-4 rounded-2xl max-w-2xl leading-relaxed ${
              m.sender === 'user'
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-tr-none'
                : 'bg-slate-950/80 border border-slate-800 text-slate-200 rounded-tl-none space-y-2'
            }`}>
              <div className="whitespace-pre-wrap">{m.text}</div>
            </div>

            {m.sender === 'user' && (
              <div className="w-8 h-8 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {isTyping && (
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono">
            <Sparkles className="w-4 h-4 animate-spin" /> CyberMind AI is reasoning...
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="glass-panel p-3 rounded-2xl flex items-center gap-3 shrink-0">
        <input
          type="text"
          placeholder="Ask: 'Why is this Windows Event suspicious?', 'Generate PowerShell block script'..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          className="bg-slate-950 border border-slate-800 text-slate-100 text-xs rounded-xl px-4 py-3 focus:outline-none focus:border-cyan-500 flex-1 font-mono"
        />
        <button
          onClick={handleSend}
          className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-bold flex items-center gap-2 shadow-lg shadow-cyan-500/25 transition-all"
        >
          <Send className="w-4 h-4" /> Send
        </button>
      </div>
    </div>
  );
}
