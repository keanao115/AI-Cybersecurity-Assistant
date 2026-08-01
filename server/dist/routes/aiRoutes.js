import { Router } from 'express';
import { chatWithSocCopilot, analyzeLogsWithGemini } from '../services/geminiAiService.js';
import { getSiemEvents } from '../services/siemCollectorService.js';
import { memoryDb } from '../db/client.js';
export const aiRouter = Router();
// POST /api/ai/chat — Real Gemini conversational SOC copilot
aiRouter.post('/chat', async (req, res) => {
    const { history, message, includeContext } = req.body;
    if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'message field is required' });
    }
    const chatHistory = Array.isArray(history)
        ? history.map((h) => ({ role: h.role, parts: h.parts }))
        : [];
    // Optionally include live SOC telemetry as context
    const context = includeContext ? {
        siemEvents: getSiemEvents().slice(0, 8),
        findings: memoryDb.findings.slice(0, 5),
        logs: memoryDb.logs.slice(0, 10),
    } : undefined;
    try {
        const reply = await chatWithSocCopilot(chatHistory, message, context);
        return res.json({ reply, timestamp: new Date().toISOString() });
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
// POST /api/ai/analyze — Real Gemini threat analysis from telemetry
aiRouter.post('/analyze', async (req, res) => {
    const { logs, findings, scan } = req.body;
    const telemetry = {
        logs: logs || memoryDb.logs,
        findings: findings || memoryDb.findings,
        scan,
        siemEvents: getSiemEvents(),
    };
    try {
        const analysis = await analyzeLogsWithGemini(telemetry);
        return res.json(analysis);
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
// GET /api/ai/status — Returns whether Gemini API is configured
aiRouter.get('/status', (req, res) => {
    const hasKey = !!process.env.GEMINI_API_KEY;
    return res.json({
        geminiConfigured: hasKey,
        model: hasKey ? 'gemini-1.5-flash' : null,
        mode: hasKey ? 'AI_POWERED' : 'RULE_BASED_FALLBACK',
        message: hasKey
            ? 'Gemini AI is active. All analysis requests are powered by Google Gemini 1.5 Flash.'
            : 'Add GEMINI_API_KEY to server/.env to enable AI-powered analysis. Currently using rule-based fallback.',
    });
});
