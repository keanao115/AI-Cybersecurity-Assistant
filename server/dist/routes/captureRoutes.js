import { Router } from 'express';
import { InterfaceManager } from '../capture/interfaceManager.js';
import { CaptureManager } from '../capture/captureManager.js';
export const captureRouter = Router();
// GET /api/capture/interfaces — List network interfaces
captureRouter.get('/interfaces', (_req, res) => {
    const interfaces = InterfaceManager.getInterfaces();
    return res.json({ interfaces, count: interfaces.length });
});
// GET /api/capture/status — Capture engine status
captureRouter.get('/status', (_req, res) => {
    const status = CaptureManager.getInstance().getStatus();
    return res.json({ activeSession: status });
});
// POST /api/capture/start — Start capture session
captureRouter.post('/start', (req, res) => {
    const { interfaceId, bpfFilter, promiscuousMode } = req.body;
    if (!interfaceId) {
        return res.status(400).json({ error: 'interfaceId is required' });
    }
    try {
        const session = CaptureManager.getInstance().startCapture({
            interfaceId,
            bpfFilter,
            promiscuousMode,
        });
        return res.json({ message: 'Capture started', session });
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
// POST /api/capture/stop — Stop capture session
captureRouter.post('/stop', (_req, res) => {
    const session = CaptureManager.getInstance().stopCapture();
    return res.json({ message: 'Capture stopped', session });
});
