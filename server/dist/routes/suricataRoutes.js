import { Router } from 'express';
import { SuricataCollectorService } from '../collectors/suricata/suricataCollector.js';
export const suricataRouter = Router();
// GET /api/suricata/status — Suricata IDS sensor health
suricataRouter.get('/status', (_req, res) => {
    return res.json(SuricataCollectorService.getInstance().getSensorStatus());
});
// POST /api/suricata/eve — Ingest Suricata EVE JSON event
suricataRouter.post('/eve', (req, res) => {
    const eveEntry = req.body;
    if (!eveEntry || typeof eveEntry !== 'object') {
        return res.status(400).json({ error: 'Valid EVE JSON entry object is required' });
    }
    try {
        const event = SuricataCollectorService.getInstance().parseEveEntry(eveEntry);
        return res.json({ message: 'Suricata EVE entry ingested', event });
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
